"""Run explicitly inside the API container after all services are ready."""
import json
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE = "http://keycloak:8080/auth"
def secret(name):return Path("/run/secrets",name).read_text().strip()
def call(method,path,data=None,token=None,form=False):
    headers={"Content-Type":"application/x-www-form-urlencoded" if form else "application/json"}
    if token:headers["Authorization"]="Bearer "+token
    body=(urlencode(data).encode() if form else json.dumps(data).encode()) if data is not None else None
    with urlopen(Request(BASE+path,data=body,headers=headers,method=method),timeout=15) as response:
        content=response.read()
        return json.loads(content) if content else None

for attempt in range(60):
    try:
        token=call("POST","/realms/master/protocol/openid-connect/token",{
            "client_id":"admin-cli","grant_type":"password","username":"bootstrap-admin",
            "password":secret("bootstrap_admin_password")},form=True)["access_token"]
        break
    except (URLError,HTTPError):
        if attempt==59:raise
        time.sleep(3)

try:
    call("GET","/admin/realms/course",token=token)
except HTTPError as error:
    if error.code!=404:raise
    call("POST","/admin/realms",json.loads(Path("/app/realm.json").read_text(encoding="utf-8")),token)

# Preserve Keycloak's default profile schema and explicitly allow the marker for administrators.
profile=call("GET","/admin/realms/course/users/profile",token=token)
profile["unmanagedAttributePolicy"]="ADMIN_EDIT"
call("PUT","/admin/realms/course/users/profile",profile,token)

clients=call("GET","/admin/realms/course/clients",token=token)
manager=next(c for c in clients if c["clientId"]=="account-manager")
management=next(c for c in clients if c["clientId"]=="realm-management")
manager["secret"]=secret("manager_client_secret")
call("PUT","/admin/realms/course/clients/"+manager["id"],manager,token)
service=call("GET","/admin/realms/course/clients/"+manager["id"]+"/service-account-user",token=token)
roles=call("GET","/admin/realms/course/clients/"+management["id"]+"/roles",token=token)
selected=[r for r in roles if r["name"] in {"manage-users","view-users","query-users"}]
call("POST","/admin/realms/course/users/"+service["id"]+"/role-mappings/clients/"+management["id"],selected,token)

def create_if_absent(username,role=None,managed=False):
    found=call("GET","/admin/realms/course/users?"+urlencode({"username":username,"exact":"true"}),token=token)
    if found:
        print(username+": already exists; password preserved")
        user=found[0]
    else:
        account={"username":username,"firstName":"Учебный","lastName":username,"email":username+"@example.test","enabled":True,
                 "credentials":[{"type":"password","value":secret("demo_password"),"temporary":True}]}
        if role=="operator":account["requiredActions"]=["CONFIGURE_TOTP"]
        if managed:account["attributes"]={"managed_by":["course-project"]}
        call("POST","/admin/realms/course/users",account,token)
        user=call("GET","/admin/realms/course/users?"+urlencode({"username":username,"exact":"true"}),token=token)[0]
        print(username+": created; change temporary password at first sign-in")
    if role:
        representation=call("GET","/admin/realms/course/roles/"+role,token=token)
        call("POST","/admin/realms/course/users/"+user["id"]+"/role-mappings/realm",[representation],token)

create_if_absent("lab.operator","operator")
create_if_absent("lab.viewer","viewer")
create_if_absent("student.demo",managed=True)
print("Bootstrap complete. Temporary passwords are in secrets/demo_password.txt on the host, not in this output.")
