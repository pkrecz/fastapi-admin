import bcrypt
from fastapi import Depends
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session, joinedload
from datetime import datetime, timedelta, timezone
from config.settings import settings
from config.database import get_db
from jose import JWTError, jwt
from . import exceptions
from .models import UserModel, RoleModel, PermissionModel


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/login/")


class FunctionRepository:

    def query_get_user_by_username(self, db, username: str):
        return db.query(UserModel).filter_by(username=username)

    def query_get_user_by_email(self, db, email: str):
        return db.query(UserModel).filter_by(email=email)

    def query_get_role_by_name(self, db, name: str):
        return db.query(RoleModel).filter_by(name=name)

    def query_get_permission_by_name(self, db, name: str):
        return db.query(PermissionModel).filter_by(name=name)

    def check_the_same_password(self, password: str, password_confirm: str):
        return bool(password == password_confirm)

    def hash_password(self, password: str):
        pwd = password.encode("utf-8")
        salt = bcrypt.gensalt()
        return str(bcrypt.hashpw(password=pwd, salt=salt).decode("utf-8"))

    def verify_password(self, password: str, hashed_password: str):
        pwd = password.encode("utf-8")
        hashed_pwd = hashed_password.encode("utf-8")
        return bool(bcrypt.checkpw(password=pwd, hashed_password=hashed_pwd))

    def get_active_status(self, db, username: str):
        return bool(db.query(UserModel).filter_by(username=username).first().is_active)

    def authenticate_user(self, db, username: str, password: str):
        user_query = self.query_get_user_by_username(db, username=username)
        if user_query.count() == 0 or self.verify_password(password, user_query.first().hashed_password) == False:
            return False
        else:
            return user_query.first()

    def create_token(self, data: dict, refresh: bool):
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

    def verify_token(self, token: str, refresh: bool):
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

    def get_roles_per_user(self, db, username: str):
            list_of_roles = []
            user_query = self.query_get_user_by_username(db, username)
            roles_of_user = jsonable_encoder(user_query.options(joinedload(UserModel.roles)).first())
            for one_role in roles_of_user["roles"]:
                list_of_roles.append(one_role["name"])
            return list(list_of_roles)

    def get_permissions_per_user(self, db, username: str):
            list_of_roles = self.get_roles_per_user(db, username)
            list_of_permissions = []
            for single_role in list_of_roles:
                if single_role == "admin":
                    list_of_permissions.append("admin")
                    return list_of_permissions
                role_query = self.query_get_role_by_name(db, single_role)
                permissions_of_role = jsonable_encoder(role_query.options(joinedload(RoleModel.permissions)).first())
                for one_permission in permissions_of_role["permissions"]:
                    list_of_permissions.append(one_permission["name"])
            list_of_permissions = list(set(list_of_permissions))
            return list(list_of_permissions)

    def check_permission(self, user, db, required_permission: str):
        permission_list = repo_functions.get_permissions_per_user(db, user.username)
        for user_permission in permission_list:
            if user_permission == required_permission or user_permission == "admin":
                return True
        raise exceptions.NoPermissionsException


class DependencyRepository:

    async def log_dependency(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
        username = repo_functions.verify_token(token=token, refresh=False)
        if username is None:
            raise exceptions.CredentialsException
        user_query = repo_functions.query_get_user_by_username(db, username=username)
        if user_query.count() == 0:
            raise exceptions.CredentialsException
        if repo_functions.get_active_status(db, user_query.first().username) == False:
            raise exceptions.UserInActiveException
        return user_query.first()

    async def refresh_token_dependency(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
        username = repo_functions.verify_token(token=token, refresh=True)
        if username is None:
            raise exceptions.CredentialsException
        user_query = repo_functions.query_get_user_by_username(db, username=username)
        if user_query.count() == 0:
            raise exceptions.CredentialsException
        if repo_functions.get_active_status(db, user_query.first().username) == False:
            raise exceptions.UserInActiveException
        return user_query.first()


repo_functions = FunctionRepository()
repo_dependency = DependencyRepository()
