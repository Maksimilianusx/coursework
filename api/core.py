"""Pure validation and access-control rules, independent of web/DB libraries."""
import re
import uuid

MANAGED_ATTRIBUTE = "course-project"
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

class ValidationError(ValueError):
    pass

def authorized(claims, method):
    roles = claims.get("realm_access", {}).get("roles", [])
    if not isinstance(roles, list):
        return False
    allowed = {"operator"} if method in WRITE_METHODS else {"operator", "viewer"}
    return bool(allowed.intersection(roles))

def validate_account(data, create=False):
    if not isinstance(data, dict):
        raise ValidationError("Ожидается JSON-объект")
    allowed = {"username", "firstName", "lastName", "email", "enabled"}
    if set(data) - allowed:
        raise ValidationError("Переданы запрещенные поля")
    if create and "username" not in data:
        raise ValidationError("Нужен username")
    if not create and "username" in data:
        raise ValidationError("Изменение username не поддерживается")
    result = {}
    for key, value in data.items():
        if key == "enabled":
            if not isinstance(value, bool):
                raise ValidationError("enabled должен быть boolean")
        else:
            if not isinstance(value, str):
                raise ValidationError("Строковое поле имеет неверный тип")
            value = value.strip()
            if len(value) > 100 or any(ord(c) < 32 for c in value):
                raise ValidationError("Поле длиннее 100 символов или содержит управляющие символы")
            if key == "username" and not re.fullmatch(r"[a-z][a-z0-9._-]{2,31}", value):
                raise ValidationError("Логин: 3–32 символа a-z, цифры, ._-; первый символ a-z")
            if key == "email" and value and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
                raise ValidationError("Некорректный email")
        result[key] = value
    if not result:
        raise ValidationError("Не указаны поля")
    if create:
        result.setdefault("enabled", False)
        result["attributes"] = {"managed_by": [MANAGED_ATTRIBUTE]}
    return result

def is_managed(user):
    return MANAGED_ATTRIBUTE in user.get("attributes", {}).get("managed_by", [])

def public_user(user):
    return {k: user.get(k, "" if k != "enabled" else False)
            for k in ("id", "username", "firstName", "lastName", "email", "enabled")}

def valid_id(value):
    try:
        return str(uuid.UUID(value)) == value.lower()
    except (ValueError, AttributeError):
        return False
