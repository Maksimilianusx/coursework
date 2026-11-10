"""Offline checks available without Docker or third-party Python packages."""
import ast
import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
for file in root.rglob("*.py"):
    if ".venv" not in file.parts:ast.parse(file.read_text(encoding="utf-8"),filename=str(file))
realm=json.loads((root/"api/realm.json").read_text(encoding="utf-8"))
assert realm["accessTokenLifespan"]==120
ui=next(c for c in realm["clients"] if c["clientId"]=="account-ui")
assert ui["publicClient"] and not ui["directAccessGrantsEnabled"]
assert ui["attributes"]["pkce.code.challenge.method"]=="S256"
assert ui["redirectUris"]==["https://iam.lab.test/"]
assert "secret" not in ui
assert any(m["config"].get("included.custom.audience")=="account-api" for m in ui["protocolMappers"])
print("PASS: Python syntax, realm configuration, PKCE, redirect URI and API audience")
