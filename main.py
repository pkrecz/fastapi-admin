from fastapi import FastAPI
from config.settings import settings
from config import registry


def start_application():
    app = FastAPI(
                    title=settings.title,
                    version=settings.version,
                    docs_url=settings.docs_url,
                    redoc_url=None,
                    contact={
                                "name": "Piotr",
                                "email": "pkrecz@poczta.onet.pl"})
    registry.create_tables()
    registry.load_routers(app)
    registry.create_role_and_permissions()
    registry.create_admin_user(settings.ADMIN_USER_NAME)
    registry.assign_role_to_admin_user(settings.ADMIN_USER_NAME)
    return app


app = start_application()
