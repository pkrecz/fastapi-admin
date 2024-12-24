from fastapi import FastAPI
from config.settings import settings
from config.database import get_db
from config import registry

db = next(get_db())


def lifespan(app: FastAPI):
    registry.init_models()
    registry.init_data(db)
    registry.init_routers(app)
    yield


app = FastAPI(
                lifespan=lifespan,
                title=settings.title,
                version=settings.version,
                docs_url=settings.docs_url,
                redoc_url=None,
                contact={
                            "name": "Piotr",
                            "email": "pkrecz@poczta.onet.pl"})
