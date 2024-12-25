import bcrypt
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from fastapi_filter.contrib.sqlalchemy import Filter
from sqlalchemy import select, exists
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from typing import TypeVar, Annotated
from datetime import datetime, timedelta, timezone
from config.settings import settings
from config.database import Base
from . import exceptions


Model = TypeVar("Model", bound=Base)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/login/")


class AuthenticationRepository:

    def __init__(self, db: Session = None, model: Model = None):
        self.db = db
        self.model = model


    def check_if_exists_user_by_username(self, username: str) -> bool:
        query = select(self.model).filter_by(username=username)
        query = exists(query).select()
        return self.db.scalar(query)


    def check_if_exists_user_by_email(self, email: str) -> bool:
        query = select(self.model).filter_by(email=email)
        query = exists(query).select()
        return self.db.scalar(query)


    def get_user_by_username(self, username: str) -> str:
        query = select(self.model).filter_by(username=username)
        return self.db.scalar(query)


    def check_the_same_password(self, password: str, password_confirm: str) -> bool:
        return bool(password == password_confirm)


    def hash_password(self, password: str) -> str:
        pwd = password.encode("utf-8")
        salt = bcrypt.gensalt()
        return str(bcrypt.hashpw(password=pwd, salt=salt).decode("utf-8"))


    def verify_password(self, password: str, hashed_password: str) -> bool:
        pwd = password.encode("utf-8")
        hashed_pwd = hashed_password.encode("utf-8")
        return bool(bcrypt.checkpw(password=pwd, hashed_password=hashed_pwd))


    def get_active_status(self, username: str) -> bool:
        query = select(self.model).filter_by(username=username)
        return bool(self.db.scalar(query).is_active)


    def authenticate_user(self, username: str, password: str) -> Model:
        instance = self.get_user_by_username(username=username)
        if instance and self.verify_password(password, instance.hashed_password) == True:
            return instance
        else:
            return False


    def create_token(self, data: dict, refresh: bool) -> str:
        to_encode = data.copy()
        if refresh:
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
            secret_key = settings.REFRESH_SECRET_KEY
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            secret_key = settings.ACCESS_SECRET_KEY
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=settings.ALGORITHM)
        return str(encoded_jwt)


    def verify_token(self, token: str, refresh: bool) -> str:
        try:
            if refresh:
                payload = jwt.decode(token, settings.REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
            else:
                payload = jwt.decode(token, settings.ACCESS_SECRET_KEY, algorithms=[settings.ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                return None
            return username
        except jwt.ExpiredSignatureError:
            raise exceptions.TokenExpiredException
        except JWTError:
            return None


class AuthorizationRepository:

    def __init__(self, db: Session, model: Model):
        self.db = db
        self.model = model


    def check_if_exists_role_by_name(self, role: str) -> bool:
        query = select(self.model).filter_by(name=role)
        query = exists(query).select()
        return self.db.scalar(query)


    def get_role_by_name(self, role: str) -> str:
        query = select(self.model).filter_by(name=role)
        return self.db.scalar(query)


    def get_permission_by_name(self, permission: str) -> str:
        query = select(self.model).filter_by(name=permission)
        return self.db.scalar(query)


    def get_all_permission(self) -> Model:
        query = select(self.model)
        return self.db.scalars(query).all()


class CrudOperationRepository:

    def __init__(self, db: Session, model: Model):
        self.db = db
        self.model = model


    def get_by_id(self, id: int) -> Model:
        return self.db.get(self.model, id)


    def get_all(self, filter: Filter = None) -> Model:
        query = select(self.model)
        if filter is not None:
            query = filter.filter(query)
            query = filter.sort(query)
        return self.db.scalars(query).all()


    def create(self, data: dict) -> Model:
        record = self.model(**data)
        self.db.add(record)
        self.db.flush()
        self.db.refresh(record)
        return record


    def update(self, record: Model, data: Annotated[BaseModel, dict]) -> Model:
        if isinstance(data, BaseModel):
            data = data.model_dump(exclude_none=True)
        for key, value in data.items():
            setattr(record, key, value)
        self.db.merge(record)
        self.db.flush()
        self.db.refresh(record)
        return record


    def delete(self, record: Model) -> bool:
        if record is not None:
            self.db.delete(record)
            self.db.flush()
            return True
        else:
            return False


    def retrieve(self, record: Model) -> Model:
        return record


    def list(self, record: Model) -> list[Model]:
        return record
