import logging
from sqlalchemy.orm import Session
from config.database import Base, get_engine
from config.settings import settings
from app_admin import controlers as admin_controlers
from app_admin import initdata 
from app_application import controlers as application_controlers


logger = logging.getLogger("uvicorn.error")


def init_models():
    Base.metadata.create_all(bind=get_engine())
    logger.info("Tables has been created.")


def init_routers(app):
    app.include_router(
                        router=admin_controlers.router_authentication,
                        prefix="/admin",
                        tags=["Authentication"])
    app.include_router(
                        router=admin_controlers.router_authorization,
                        prefix="/admin",
                        tags=["Authorization"])
    app.include_router(
                        router=application_controlers.router,
                        prefix="",
                        tags=["Application"])
    logger.info("Routes has been loaded.")


def init_data(db: Session):
    initdata.create_admin_user(db, settings.ADMIN_USER_NAME)
    initdata.create_role_admin(db)
    initdata.create_permissions(db)
    initdata.assign_role_to_admin_user(db, settings.ADMIN_USER_NAME)
