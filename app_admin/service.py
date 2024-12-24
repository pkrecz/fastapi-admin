from typing import TypeVar
from pydantic import BaseModel
from fastapi import status
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from config.database import Base
from . import exceptions
from .repository import AuthenticationRepository, AuthorizationRepository, CrudOperationRepository
from .models import UserModel, RoleModel, PermissionModel


Model = TypeVar("Model", bound=Base)


class AuthenticationService:

    def __init__(self, db: Session, cuser: str = None):
        self.db = db
        self.cuser = cuser
        self.model = UserModel
        self.auth = AuthenticationRepository(self.db, UserModel)
        self.crud = CrudOperationRepository(self.db, UserModel)


    def authentication_register_user(self, data: BaseModel) -> Model:
        try:
            if self.auth.check_if_exists_user_by_username(data.username):
                raise exceptions.UserExistsException
            if self.auth.check_if_exists_user_by_email(data.email):
                raise exceptions.EmailExistsException
            if self.auth.check_the_same_password(data.password, data.password_confirm) == False:
                raise exceptions.NotTheSamePasswordException
            input = {
                "username": data.username,
                "full_name": data.full_name,
                "email": data.email,
                "hashed_password": self.auth.hash_password(data.password)}
            instance = self.model(**input)
            return self.crud.create(instance)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authentication_update_user(self, data: BaseModel) -> Model:
        try:
            instance = self.auth.get_user_by_username(self.cuser.username)
            if not instance:
                raise exceptions.UserNotFoundException
            return self.crud.update(instance, data)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authentication_delete_user(self):
        try:
            instance = self.auth.get_user_by_username(self.cuser.username)
            if not instance:
                raise exceptions.UserNotFoundException
            if not self.crud.delete(instance):
                raise
            return JSONResponse(content={"message": "User deleted successfully."}, status_code=status.HTTP_200_OK)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authentication_change_password(self, data: BaseModel):
        try:
            instance = self.auth.get_user_by_username(self.cuser.username)
            if not instance:
                raise exceptions.UserNotFoundException
            if self.auth.check_the_same_password(data.new_password, data.new_password_confirm) == False:
                raise exceptions.NotTheSamePasswordException
            if self.auth.verify_password(data.old_password, instance.hashed_password) == False:
                raise exceptions.IncorrectPasswordException
            data = {"hashed_password": self.auth.hash_password(data.new_password)}
            self.crud.update(instance, data)
            return JSONResponse(content={"message": "Password changed successfully."}, status_code=status.HTTP_200_OK)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authentication_login(self, data: OAuth2PasswordBearer):
        try:
            user = self.auth.authenticate_user(data.username, data.password)
            if not user:
                raise exceptions.CredentialsException
            if self.auth.get_active_status(user.username) == False:
                raise exceptions.UserInActiveException
            access_token = self.auth.create_token(data={"sub": user.username}, refresh=False)
            refresh_token = self.auth.create_token(data={"sub": user.username}, refresh=True)
            return JSONResponse(content={"access_token": access_token, "refresh_token": refresh_token}, status_code=status.HTTP_200_OK)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authentication_refresh(self):
        try:
            access_token = self.auth.create_token(data={"sub": self.cuser.username}, refresh=False)
            return JSONResponse(content={"access_token": access_token}, status_code=status.HTTP_200_OK)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


class AuthorizationService:

    def __init__(self, db: Session, cuser: str = None):
        self.db = db
        self.cuser = cuser
        self.authentication_user = AuthenticationRepository(self.db, UserModel)
        self.authorization_role = AuthorizationRepository(self.db, RoleModel)
        self.authorization_permission = AuthorizationRepository(self.db, PermissionModel)
        self.crud = CrudOperationRepository(self.db, RoleModel)


    def authorization_create_role(self, data: BaseModel) -> Model:
        try:
            if self.authorization_role.check_if_exists_role_by_name(data.name):
                raise exceptions.BadRequestException("Role already exists.")
            instance = RoleModel(**data.model_dump())
            return self.crud.create(instance)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authorization_assign_role_to_user(self, username: str, role: str):
        try:
            user = self.authentication_user.get_user_by_username(username)
            role = self.authorization_role.get_role_by_name(role)
            if not user or not role:
                raise exceptions.NotFoundException("User or role was not found.")
            try:
                queue = user
                queue.roles.append(role)
                self.db.flush()
            except:
                raise exceptions.BadRequestException("Assigment already exists.")
            return JSONResponse(content={"message": "Role assigned to user."}, status_code=status.HTTP_200_OK)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authorization_unassign_role_from_user(self, username: str, role: str):
        try:
            user = self.authentication_user.get_user_by_username(username)
            role = self.authorization_role.get_role_by_name(role)
            if not user or not role:
                raise exceptions.NotFoundException("User or role was not found.")
            try:
                queue = user
                queue.roles.remove(role)    
                self.db.flush()
            except:
                raise exceptions.BadRequestException("Assigment was not found.")
            return JSONResponse(content={"message": "Role unassigned from user."}, status_code=status.HTTP_200_OK)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authorization_get_role_per_user(self, username: str):
        try:
            user = self.authentication_user.get_user_by_username(username)
            if not user:
                raise exceptions.UserNotFoundException
            return user
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authorization_get_user_per_role(self, role: str):
        try:
            role = self.authorization_role.get_role_by_name(role)
            if not role:
                raise exceptions.NotFoundException("Role was not found.")
            return role
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authorization_assign_permission_to_role(self, role: str, permission: str):
        try:
            role = self.authorization_role.get_role_by_name(role)
            permission = self.authorization_permission.get_permission_by_name(permission)
            if not role or not permission:
                raise exceptions.NotFoundException("Role or permission was not found.")
            try:
                queue = role
                queue.permissions.append(permission)
                self.db.flush()
            except:
                raise exceptions.BadRequestException("Assigment already exists.")
            return JSONResponse(content={"message": "Permission assigned to role."}, status_code=status.HTTP_200_OK)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authorization_unassign_permission_from_role(self, role: str, permission: str):
        try:
            role = self.authorization_role.get_role_by_name(role)
            permission = self.authorization_permission.get_permission_by_name(permission)
            if not role or not permission:
                raise exceptions.NotFoundException("Role or permission was not found.")
            try:
                queue = role
                queue.permissions.remove(permission)
                self.db.flush()
            except:
                raise exceptions.BadRequestException("Assigment was not found.")
            return JSONResponse(content={"message": "Permission unassigned from role."}, status_code=status.HTTP_200_OK)
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authorization_get_permission_per_user(self, username: str):
        try:
            user = self.authentication_user.get_user_by_username(username)
            if not user:
                raise exceptions.UserNotFoundException
            return user
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


    def authorization_get_all_permission(self):
        try:
            permission = self.authorization_permission.get_all_permission()
            if not permission:
                raise exceptions.BadRequestException("No permission found.")
            return permission
        except Exception as exception:
            return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)
