from functools import wraps
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload
from config.database import get_db
from . import exceptions
from .models import UserModel, RoleModel



def get_roles_per_user(
                                db: Session,
                                username: str) -> list:
        list_of_roles = list()
        query = select(UserModel).options(joinedload(UserModel.roles)).filter_by(username=username)
        roles_of_user = jsonable_encoder(db.scalar(query))
        for one_role in roles_of_user["roles"]:
            list_of_roles.append(one_role["name"])
        return list_of_roles


def get_permissions_per_user(
                                db: Session,
                                username: str) -> list:
        list_of_roles = get_roles_per_user(db, username)
        list_of_permissions = list()
        for single_role in list_of_roles:
            if single_role == "admin":
                list_of_permissions.append("admin")
                return list_of_permissions
            query = select(RoleModel).options(joinedload(RoleModel.permissions))
            permissions_of_role = jsonable_encoder(db.scalar(query))
            for one_permission in permissions_of_role["permissions"]:
                list_of_permissions.append(one_permission["name"])
        list_of_permissions = list(set(list_of_permissions))
        return list_of_permissions


def check_permission(
                                db: Session,
                                username: str,
                                required_permission: str) -> bool:
    permission_list = get_permissions_per_user(db, username)
    for user_permission in permission_list:
        if user_permission == required_permission or user_permission == "admin":
            return True
    raise exceptions.NoPermissionsException


def permission_required(required_permission: str):
    db = next(get_db())
    def decorator(function):
        @wraps(function)
        async def wrapper(*args, **kwargs):
            username = kwargs.get("cuser").username
            check_permission(
                                db = db,
                                username = username,
                                required_permission = required_permission)
            return await function(*args, **kwargs)
        return wrapper
    return decorator
