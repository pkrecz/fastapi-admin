import logging
from sqlalchemy import select, exists
from sqlalchemy.orm import Session
from .models import UserModel, RoleModel, PermissionModel
from .repository import AuthenticationRepository


logger = logging.getLogger("uvicorn.error")
auth = AuthenticationRepository()
permissions_to_be_created = ["example_permission"]


def create_admin_user(db: Session, username: str):
    query = select(UserModel).filter_by(username=username)
    query = exists(query).select()
    if not db.scalar(query):
        data = {"username": username,
                "full_name": "Root user",
                "email": "root@company.com",
                "hashed_password": auth.hash_password("admin")}
        instance = UserModel(**data)
        db.add(instance)
        db.commit()
    logging.info("User admin has been created.")


def create_role_admin(db: Session):
    query = select(RoleModel).filter_by(name="admin")
    query = exists(query).select()
    if not db.scalar(query):
        data = {"name": "admin"}
        instance = RoleModel(**data)
        db.add(instance)
        db.commit()
    logger.info("Role admin has been created.")


def create_permissions(db: Session):
    objects = list()
    for single_permission in permissions_to_be_created:
        query = select(PermissionModel).filter_by(name=single_permission)
        query = exists(query).select()
        if not db.scalar(query):
            data = dict()
            data["name"] = single_permission
            instance = PermissionModel(**data)
            objects.append(instance)
    db.bulk_save_objects(objects)
    db.commit()
    logger.info("Permissions has been created.")


def assign_role_to_admin_user(db: Session, username: str):
    user = db.scalar(select(UserModel).filter_by(username=username))
    role = db.scalar(select(RoleModel).filter_by(name="admin"))
    try:
        user.roles.append(role)
        db.commit()
    except:
        pass
    logger.info(f"Role admin has been assigned to '{username}' user.")
