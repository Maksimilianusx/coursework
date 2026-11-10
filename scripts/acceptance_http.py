"""Exercise a running lab through HTTPS and real Keycloak, without UI automation.

Only disposable qa-* accounts created by this run are removed on exit.
No existing password, client, role or realm configuration is changed.
"""
import argparse
import base64
import hashlib
import http.cookiejar
import json
import secrets
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse, parse_qs
from urllib.request import Request, build_opener, HTTPSHandler, HTTPCookieProcessor, HTTPRedirectHandler


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.action = None; self.fields = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'form' and a.get('id') == 'kc-form-login':
            self.action = a.get('action')
        if tag == 'input' and a.get('type') == 'hidden' and a.get('name'):
            self.fields[a['name']] = a.get('value', '')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--secrets-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base', default='https://iam.lab.test')
    args = parser.parse_args()
    ctx = ssl.create_default_context(cafile=str(args.secrets_dir/'tls.crt'))
    transport = build_opener(HTTPSHandler(context=ctx))
    base = args.base.rstrip('/')
    checks = []; created = []; managed_ids = []; tokens = {}
    run = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'base': base,
              'scope': 'Real HTTPS, Keycloak authorization-code+PKCE, Flask, PostgreSQL; no browser UI test',
              'checks': checks}
    admin = None

    def request(method, path, data=None, token=None, form=False, opener=transport):
        url = path if path.startswith('https://') else base+path
        headers = {'Accept': 'application/json'}
        body = None
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
            body = urlencode(data).encode() if form else json.dumps(data).encode()
        if token: headers['Authorization'] = 'Bearer '+token
        try:
            response = opener.open(Request(url, data=body, headers=headers, method=method), timeout=25)
        except HTTPError as e:
            response = e
        with response:
            raw = response.read()
            try: content = json.loads(raw)
            except (ValueError, UnicodeError): content = raw.decode('utf-8', errors='replace')
            return response.code, content, dict(response.headers)

    def check(name, ok, detail):
        checks.append({'name': name, 'passed': bool(ok), 'detail': detail})
        print(('PASS ' if ok else 'FAIL ')+name+': '+detail, flush=True)
        if not ok: raise AssertionError(name)

    def adm(method, path, data=None):
        status, content, headers = request(method, '/auth/admin/realms/course'+path, data, admin)
        if status >= 400: raise RuntimeError('Admin request failed: '+method+' '+path.split('?')[0]+' status='+str(status))
        return content, headers

    def login(username, password):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        state = secrets.token_urlsafe(24)
        jar = http.cookiejar.CookieJar()
        browser_http = build_opener(HTTPSHandler(context=ctx), HTTPCookieProcessor(jar))
        no_redirect = build_opener(HTTPSHandler(context=ctx), HTTPCookieProcessor(jar), NoRedirect())
        query = urlencode({'client_id':'account-ui','redirect_uri':base+'/', 'response_type':'code',
                           'scope':'openid profile email', 'state':state,
                           'code_challenge':challenge, 'code_challenge_method':'S256'})
        status, html, _ = request('GET', '/auth/realms/course/protocol/openid-connect/auth?'+query, opener=browser_http)
        form = FormParser(); form.feed(html)
        if status != 200 or not form.action: raise RuntimeError('OIDC login form unavailable')
        data = {**form.fields, 'username':username, 'password':password, 'credentialId':''}
        status, content, headers = request('POST', form.action, data, form=True, opener=no_redirect)
        location = headers.get('Location', headers.get('location',''))
        parsed = parse_qs(urlparse(location).query)
        if status != 302 or parsed.get('state') != [state] or 'code' not in parsed:
            raise RuntimeError('OIDC password step did not return authorization code; status='+str(status))
        code = parsed['code'][0]
        status, result, _ = request('POST','/auth/realms/course/protocol/openid-connect/token',
                                   {'grant_type':'authorization_code', 'client_id':'account-ui',
                                    'redirect_uri':base+'/', 'code':code, 'code_verifier':verifier}, form=True)
        if status != 200: raise RuntimeError('PKCE exchange failed; status='+str(status))
        return result['access_token'], result['expires_in']

    try:
        status, data, _ = request('GET','/health/ready')
        check('HTTPS readiness',status==200 and data.get('status')=='ready','HTTP '+str(status))
        status, discovery, _ = request('GET','/auth/realms/course/.well-known/openid-configuration')
        check('OIDC issuer',status==200 and discovery.get('issuer')==base+'/auth/realms/course','external issuer matches')
        status, data, _ = request('POST','/auth/realms/master/protocol/openid-connect/token',
            {'client_id':'admin-cli','grant_type':'password','username':'bootstrap-admin',
             'password':(args.secrets_dir/'bootstrap_admin_password.txt').read_text().strip()},form=True)
        if status!=200:raise RuntimeError('Bootstrap administrator unavailable; status='+str(status))
        admin=data['access_token']
        clients,_=adm('GET','/clients?clientId=account-ui');client=clients[0]
        check('PKCE client configuration',client.get('attributes',{}).get('pkce.code.challenge.method')=='S256' and not client.get('directAccessGrantsEnabled'), 'S256 required; password grant disabled for browser client')
        for role in ('operator','viewer'):
            username='qa-'+role+'-'+run;password='Qa1!'+secrets.token_urlsafe(24)
            _,headers=adm('POST','/users',{'username':username,'firstName':'Проверка','lastName':role,
                'email':username+'@example.test','emailVerified':True,'enabled':True,'requiredActions':[],
                'credentials':[{'type':'password','value':password,'temporary':False}]})
            users,_=adm('GET','/users?'+urlencode({'username':username,'exact':'true'}));user=users[0];created.append(user['id'])
            role_rep,_=adm('GET','/roles/'+role)
            adm('POST','/users/'+user['id']+'/role-mappings/realm',[role_rep])
            token,ttl=login(username,password);tokens[role]=token
            status,me,_=request('GET','/api/me',token=token)
            check('OIDC '+role,status==200 and me.get('can_write')==(role=='operator'),'authorization code + PKCE; HTTP '+str(status)+'; token TTL '+str(ttl))
        status,_,_=request('GET','/api/users')
        check('Anonymous read denied',status==401,'HTTP '+str(status))
        status,_,_=request('GET','/api/users',token=tokens['operator'][:-10]+'abcdefghij')
        check('Tampered token denied',status==401,'HTTP '+str(status))
        username='qa-record-'+run
        payload={'username':username,'firstName':'Учебный','lastName':'Пользователь','email':username+'@example.test','enabled':True}
        status,_,_=request('POST','/api/users',payload,tokens['viewer'])
        check('Viewer write denied',status==403,'HTTP '+str(status))
        status,created_data,_=request('POST','/api/users',payload,tokens['operator'])
        check('Create user',status==200 and created_data.get('status')=='succeeded','HTTP '+str(status))
        status,listing,_=request('GET','/api/users',token=tokens['operator'])
        matching=[u for u in listing.get('items',[]) if u.get('username')==username]
        check('Read created user',status==200 and len(matching)==1,'created object found in managed list')
        uid=matching[0]['id'];managed_ids.append(uid)
        status,_,_=request('PUT','/api/users/'+uid,{'firstName':'Изменено'},tokens['operator'])
        status2,changed,_=request('GET','/api/users/'+uid,token=tokens['operator'])
        check('Update and reread',status==200 and status2==200 and changed.get('firstName')=='Изменено'
              and changed.get('lastName')==payload['lastName'] and changed.get('email')==payload['email'],
              'new attribute persisted; unchanged name and email preserved')
        status,_,_=request('PUT','/api/users/'+uid,{'enabled':False},tokens['operator'])
        status2,changed,_=request('GET','/api/users/'+uid,token=tokens['operator'])
        check('Disable user',status==200 and status2==200 and changed.get('enabled') is False
              and changed.get('firstName')=='Изменено' and changed.get('lastName')==payload['lastName']
              and changed.get('email')==payload['email'],'enabled=false; profile attributes preserved')
        status,_,_=request('PUT','/api/users/'+created[1],{'firstName':'SHOULD NOT CHANGE'},tokens['operator'])
        check('Unmanaged account protected',status==404,'HTTP 404 for QA viewer without managed marker')
        status,_,_=request('DELETE','/api/users/'+uid,token=tokens['operator'])
        status2,_,_=request('GET','/api/users/'+uid,token=tokens['operator'])
        check('Delete user',status==200 and status2==404,'delete succeeded; reread HTTP 404')
        managed_ids.remove(uid)
        status,audit,_=request('GET','/api/operations',token=tokens['viewer'])
        own=[o for o in audit.get('items',[]) if o.get('actor')==created[0] and o.get('target') in (username,uid)]
        check('Audit persisted',status==200 and len(own)==4 and all(o['status']=='succeeded' for o in own),'four CRUD operations persisted; viewer can read audit')
        report['passed']=True
    except Exception as exc:
        report['passed']=False; report['error']=type(exc).__name__+': '+str(exc)
        print('ERROR '+report['error'],flush=True)
    finally:
        cleanup_errors=[]
        for uid in managed_ids+created:
            try:adm('DELETE','/users/'+uid)
            except Exception:cleanup_errors.append(uid)
        report['cleanup_errors']=cleanup_errors
        report['finished_at']=datetime.now(timezone.utc).isoformat()
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    return 0 if report.get('passed') and not report['cleanup_errors'] else 1


if __name__=='__main__':raise SystemExit(main())
