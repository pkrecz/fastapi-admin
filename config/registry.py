import logging
from fastapi import Depends
from config.database import engine, get_db

# app_admin imports ...
from app_admin import models as admin_models
from app_admin import controlers as admin_controlers
from app_admin.repository import repo_dependency, repo_functions
from app_admin.models import UserModel, RoleModel, PermissionModel

# app_application imports ...
from app_application import controlers as application_controlers


logger = logging.getLogger("uvicorn.error")


def create_tables():
    admin_models.Base.metadata.create_all(bind=engine)
    logger.info("Tables has been created.")


def load_routers(application):

    application.include_router(router=admin_controlers.router_nolog,
                                prefix="/admin",
                                tags=["Authentication"])

    application.include_router(router=admin_controlers.router_user,
                                prefix="/admin",
                                dependencies=[Depends(repo_dependency.log_dependency)],
                                tags=["Authentication"])

    application.include_router(router=admin_controlers.router_role,
                                prefix="/admin",
                                dependencies=[Depends(repo_dependency.log_dependency)],
                                tags=["Authorization"])
    application.include_router(router=application_controlers.router,
                                prefix="",
                                dependencies=[Depends(repo_dependency.log_dependency)],
                                tags=["Application"])
    logger.info("Routes has been loaded.")


def create_role_and_permissions():

    db = next(get_db())

    perm_to_be_created = []
    perm_to_be_created.extend(admin_controlers.req_perm_api_list)
    objects = []

    for single_permission in perm_to_be_created:
        if db.query(PermissionModel).filter_by(name=single_permission).count() == 0:
            data = {}
            data["name"] = single_permission
            instance = PermissionModel(**data)
            objects.append(instance)
    db.bulk_save_objects(objects)
    db.commit()
    logger.info("Permissions has been created.")

    if db.query(RoleModel).filter_by(name="admin").count() == 0:
        data = {"name": "admin"}
        instance = RoleModel(**data)
        db.add(instance)
        db.commit()
    logger.info("Role admin has been created.")


def create_admin_user(username: str):

    db = next(get_db())
    if db.query(UserModel).filter_by(username=username).count() == 0:
        data = {"username": username,
                "full_name": "Root user",
                "email": "root@company.com",
                "hashed_password": repo_functions.hash_password("admin")}
        instance = UserModel(**data)
        db.add(instance)
        db.commit()
    logger.info("User admin has been created.")


def assign_role_to_admin_user(username: str):

    db = next(get_db())
    user = db.query(UserModel).filter_by(username=username).first()
    role = db.query(RoleModel).filter_by(name="admin").first()
    try:
        user.roles.append(role)
        db.commit()
    except:
        pass
    logger.info(f"Role admin has been assigned to '{username}' user.")
