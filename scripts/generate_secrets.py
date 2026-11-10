"""Run on the lab host. Never overwrites existing passwords or keys."""
import os
import secrets
import shutil
import subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
folder=root/"secrets"
folder.mkdir(exist_ok=True)
try:folder.chmod(0o700)
except OSError:pass
for name in ("app_db_password","app_db_admin_password","identity_db_password","identity_db_admin_password","manager_client_secret","bootstrap_admin_password","demo_password"):
    target=folder/(name+".txt")
    if not target.exists():
        with target.open("x",encoding="utf-8") as out:out.write("Aa1!"+secrets.token_urlsafe(30)+"\n")
        # The private 0700 parent protects host access. File readability is needed
        # by non-root container UIDs because local Compose secrets are bind mounts.
        try:target.chmod(0o644)
        except OSError:pass
    print(name+": present")
if not (folder/"tls.crt").exists() and not (folder/"tls.key").exists():
    if not shutil.which("openssl"):
        raise SystemExit("Install OpenSSL, then rerun to create the local TLS certificate.")
    subprocess.run(["openssl","req","-x509","-nodes","-newkey","rsa:3072","-days","30",
        "-keyout",str(folder/"tls.key"),"-out",str(folder/"tls.crt"),"-subj","/CN=iam.lab.test",
        "-addext","subjectAltName=DNS:iam.lab.test"],check=True)
    (folder/"tls.key").chmod(0o600)
elif not all((folder/n).exists() for n in ("tls.crt","tls.key")):
    raise SystemExit("Only one TLS file exists; inspect it manually before generating a pair.")
print("Keep secrets/ private. Trust only this lab certificate, or replace it with an issued certificate.")
