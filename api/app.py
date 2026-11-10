import json
import os
import time
import uuid
from functools import wraps
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import jwt
import psycopg
from flask import Flask, g, jsonify, request
from psycopg.rows import dict_row

from core import ValidationError, authorized, is_managed, public_user, valid_id, validate_account

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
INTERNAL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080/auth")
REALM = "course"
ISSUER = "https://iam.lab.test/auth/realms/course"
jwks = jwt.PyJWKClient(f"{INTERNAL}/realms/{REALM}/protocol/openid-connect/certs", timeout=5)

class PartialChangeError(Exception):
    """Profile changed, but a subsequent session logout could not be confirmed."""

def secret(name):
    return Path("/run/secrets", name).read_text(encoding="utf-8").strip()

def connect():
    return psycopg.connect(host="app-db", dbname="audit", user="audit", password=secret("app_db_password"),
                           connect_timeout=5, row_factory=dict_row)

def kc(method, suffix, body=None, token=None, form=False):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        data = urlencode(body).encode() if form else json.dumps(body).encode()
    if token:
        headers["Authorization"] = "Bearer " + token
    req = Request(INTERNAL + suffix, data=data, headers=headers, method=method)
    with urlopen(req, timeout=10) as response:
        raw = response.read()
        return json.loads(raw) if raw else None

def service_token():
    # No token or secret is written to log or database.
    return kc("POST", f"/realms/{REALM}/protocol/openid-connect/token", {
        "grant_type": "client_credentials", "client_id": "account-manager",
        "client_secret": secret("manager_client_secret")}, form=True)["access_token"]

def protected(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Требуется токен"), 401
        token = header[7:]
        try:
            signing = jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(token, signing.key, algorithms=["RS256"], audience="account-api",
                                issuer=ISSUER, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except jwt.PyJWKClientConnectionError:
            return jsonify(error="Провайдер ключей недоступен"), 503
        except jwt.PyJWTError as exc:
            app.logger.warning(
                "jwt_rejected reason=%s",
                type(exc).__name__
            )
            return jsonify(error="Неверный или истекший токен"), 401
        if not authorized(claims, request.method):
            return jsonify(error="Недостаточно прав"), 403
        g.actor = claims["sub"]
        g.login = claims.get("preferred_username", g.actor)
        g.can_write = authorized(claims, "POST")
        return fn(*args, **kwargs)
    return wrapper

@app.errorhandler(ValidationError)
def invalid(error):
    return jsonify(error=str(error)), 400

@app.errorhandler(HTTPError)
def upstream_http(error):
    code = error.code if error.code in (400, 404, 409) else 502
    return jsonify(error="Операция отклонена сервисом учетных записей", upstream_status=error.code), code

@app.errorhandler(URLError)
@app.errorhandler(TimeoutError)
@app.errorhandler(psycopg.Error)
def unavailable(error):
    app.logger.error("dependency_failure type=%s", type(error).__name__)
    return jsonify(error="Зависимый сервис недоступен"), 503

def managed_user(user_id, token):
    if not valid_id(user_id):
        raise ValidationError("Неверный идентификатор")
    user = kc("GET", f"/admin/realms/{REALM}/users/{user_id}", token=token)
    if not is_managed(user):
        return None
    return user

def mutate(action, target, callback):
    # Audit intent is committed BEFORE the remote side effect. No distributed transaction is claimed.
    operation_id = str(uuid.uuid4())
    with connect() as conn:
        conn.execute("INSERT INTO operations(id,actor,action,target,status) VALUES(%s,%s,%s,%s,'pending')",
                     (operation_id, g.actor, action, target))
    try:
        result = callback()
    except PartialChangeError:
        with connect() as conn:
            conn.execute("UPDATE operations SET status='uncertain',finished_at=now() WHERE id=%s", (operation_id,))
        return jsonify(error="Профиль изменен, завершение сессий не подтверждено. Нужна сверка",operation_id=operation_id), 502
    except HTTPError as exc:
        status = "failed" if exc.code < 500 else "uncertain"
        with connect() as conn:
            conn.execute("UPDATE operations SET status=%s,finished_at=now() WHERE id=%s", (status,operation_id))
        raise
    except (URLError, TimeoutError):
        with connect() as conn:
            conn.execute("UPDATE operations SET status='uncertain',finished_at=now() WHERE id=%s",(operation_id,))
        return jsonify(error="Результат операции неизвестен. Проверьте учетную запись перед повтором",operation_id=operation_id), 502
    try:
        with connect() as conn:
            conn.execute("UPDATE operations SET status='succeeded',finished_at=now() WHERE id=%s", (operation_id,))
    except psycopg.Error:
        # Remote effect may already be committed; do not report success or retry it automatically.
        return jsonify(error="Изменение отправлено, завершение журнала не подтверждено. Нужна сверка",operation_id=operation_id), 502
    return jsonify(status="succeeded",operation_id=operation_id, result=result)

@app.get("/health/live")
def live():
    return {"status": "up"}

@app.get("/health/ready")
def ready():
    with connect() as conn:
        conn.execute("SELECT 1 FROM operations LIMIT 1")
    kc("GET", f"/realms/{REALM}/.well-known/openid-configuration")
    return {"status": "ready"}

@app.get("/api/me")
@protected
def me():
    return {"sub":g.actor,"username":g.login,"can_write":g.can_write}

@app.get("/api/users")
@protected
def list_users():
    offset = request.args.get("first", "0")
    if not offset.isdigit() or int(offset) > 100000:
        raise ValidationError("Неверное смещение")
    users = kc("GET", f"/admin/realms/{REALM}/users?" + urlencode({"q":"managed_by:course-project","first":offset,"max":50,"briefRepresentation":"false"}), token=service_token())
    return {"items":[public_user(u) for u in users if is_managed(u)], "first":int(offset),"page_size":50}

@app.post("/api/users")
@protected
def create_user():
    data = validate_account(request.get_json(silent=True), create=True)
    token = service_token()
    return mutate("create",data["username"],lambda:kc("POST", f"/admin/realms/{REALM}/users",data,token))

@app.get("/api/users/<user_id>")
@protected
def get_user(user_id):
    user = managed_user(user_id, service_token())
    return (public_user(user),200) if user else (jsonify(error="Учетная запись не управляется этим приложением"),404)

@app.put("/api/users/<user_id>")
@protected
def update_user(user_id):
    data = validate_account(request.get_json(silent=True))
    token = service_token()
    user = managed_user(user_id,token)
    if not user:
        return jsonify(error="Учетная запись не управляется этим приложением"),404
    # Keycloak's user-profile update treats omitted profile attributes as absent.
    # Preserve existing fields when the UI sends only an enabled-state change.
    data = {key: user[key] for key in ("username", "firstName", "lastName", "email", "enabled", "emailVerified")
            if key in user} | data
    data["attributes"] = user.get("attributes",{})
    if "email" in data and data["email"] != user.get("email", ""):
        data["emailVerified"] = False
    def change():
        kc("PUT", f"/admin/realms/{REALM}/users/{user_id}",data,token)
        if data.get("enabled") is False:
            try:
                kc("POST", f"/admin/realms/{REALM}/users/{user_id}/logout",token=token)
            except (HTTPError, URLError, TimeoutError) as error:
                raise PartialChangeError() from error
    return mutate("update",user_id,change)

@app.delete("/api/users/<user_id>")
@protected
def delete_user(user_id):
    token = service_token()
    if not managed_user(user_id,token):
        return jsonify(error="Учетная запись не управляется этим приложением"),404
    return mutate("delete",user_id,lambda:kc("DELETE", f"/admin/realms/{REALM}/users/{user_id}",token=token))

@app.get("/api/operations")
@protected
def operations():
    with connect() as conn:
        rows = conn.execute("SELECT id,actor,action,target,status,created_at,finished_at FROM operations ORDER BY created_at DESC LIMIT 100").fetchall()
    return {"items":rows}
