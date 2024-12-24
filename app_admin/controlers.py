from fastapi import APIRouter, status, Depends
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_restful.cbv import cbv
from sqlalchemy.orm import Session
from config.database import get_db
from .service import AuthenticationService, AuthorizationService
from .dependency import Dependency
from .schemas import (UserCreateBase, UserViewBase, UserUpdateBase, UserChangePasswordBase,
                      TokenAccessRefreshBase, TokenAccessBase,
                      RoleBase, UserWithRoleBase, RoleWithUserBase, UserWithPermissionBase, PermissionBase)
from .models import UserModel


router_nolog = APIRouter()


router_authentication = APIRouter()
router_authorization = APIRouter()
dependency = Dependency()


@cbv(router_authentication)
class APIAuthenticationClass:

    db: Session = Depends(get_db)


    @router_authentication.post(path="/register/", status_code=status.HTTP_201_CREATED, response_model=UserViewBase)
    async def register_user(
                            self,
                            data: UserCreateBase):
        service = AuthenticationService(db=self.db)
        return service.authentication_register_user(data=data)


    @router_authentication.put(path="/update/", status_code=status.HTTP_200_OK, response_model=UserViewBase)
    async def update_user(
                            self,
                            data: UserUpdateBase,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthenticationService(db=self.db, cuser=cuser)
        return service.authentication_update_user(data=data)


    @router_authentication.delete(path="/delete/", status_code=status.HTTP_200_OK)
    async def delete_user(
                            self,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthenticationService(db=self.db, cuser=cuser)
        return service.authentication_delete_user()


    @router_authentication.put(path="/change_password/", status_code=status.HTTP_200_OK)
    async def change_password(
                            self,
                            data: UserChangePasswordBase,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthenticationService(db=self.db, cuser=cuser)
        return service.authentication_change_password(data=data)


    @router_authentication.post(path="/login/", status_code=status.HTTP_200_OK, response_model=TokenAccessRefreshBase)
    async def login(
                            self,
                            data: OAuth2PasswordRequestForm = Depends()):
        service = AuthenticationService(db=self.db)
        return service.authentication_login(data=data)


    @router_authentication.post(path="/refresh/", status_code=status.HTTP_200_OK, response_model=TokenAccessBase)
    async def refresh(
                            self,
                            cuser: UserModel = Depends(dependency.refresh_token_dependency)):
        service = AuthenticationService(db=self.db, cuser=cuser)
        return service.authentication_refresh()


@cbv(router_authorization)
class APIAuthorizationClass:

    db: Session = Depends(get_db)

    @router_authorization.post(path="/create_role/", status_code=status.HTTP_201_CREATED, response_model=RoleBase)
    async def create_role(
                            self,
                            data: RoleBase,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthorizationService(db=self.db, cuser=cuser)
        return service.authorization_create_role(data=data)


    @router_authorization.post(path="/assign_role/{username}/role/{role}/", status_code=status.HTTP_200_OK)
    async def assign_role_to_user(
                            self,
                            username: str,
                            role: str,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthorizationService(db=self.db, cuser=cuser)
        return service.authorization_assign_role_to_user(username=username, role=role)


    @router_authorization.post(path="/unassign_role/{username}/role/{role}/", status_code=status.HTTP_200_OK)
    async def unassign_role_to_user(
                            self,
                            username: str,
                            role: str,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthorizationService(db=self.db, cuser=cuser)
        return service.authorization_unassign_role_from_user(username=username, role=role)


    @router_authorization.get(path="/role_per_user/{username}/", status_code=status.HTTP_200_OK, response_model=UserWithRoleBase)
    async def get_role_per_user(
                            self,
                            username: str,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthorizationService(db=self.db, cuser=cuser)
        return service.authorization_get_role_per_user(username=username)


    @router_authorization.get(path="/user_per_role/{role}/", status_code=status.HTTP_200_OK, response_model=RoleWithUserBase)
    async def get_user_per_role(
                            self,
                            role: str,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthorizationService(db=self.db, cuser=cuser)
        return service.authorization_get_user_per_role(role=role)


    @router_authorization.post(path="/assign_permission/{role}/permission/{permission}/", status_code=status.HTTP_200_OK)
    async def assign_permission_to_role(
                            self,
                            role: str,
                            permission: str,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthorizationService(db=self.db, cuser=cuser)
        return service.authorization_assign_permission_to_role(role=role, permission=permission)


    @router_authorization.post(path="/unassign_permission/{role}/permission/{permission}/", status_code=status.HTTP_200_OK)
    async def unassign_permission_from_role(
                            self,
                            role: str,
                            permission: str,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthorizationService(db=self.db, cuser=cuser)
        return service.authorization_unassign_permission_from_role(role=role, permission=permission)


    @router_authorization.get(path="/permission_per_user/{username}/", status_code=status.HTTP_200_OK, response_model=UserWithPermissionBase)
    async def get_permission_per_user(
                            self,
                            username: str,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthorizationService(db=self.db, cuser=cuser)
        return service.authorization_get_permission_per_user(username=username)


    @router_authorization.get(path="/permission_all/", status_code=status.HTTP_200_OK, response_model=list[PermissionBase])
    async def get_all_permission(
                            self,
                            cuser: UserModel = Depends(dependency.log_dependency)):
        service = AuthorizationService(db=self.db, cuser=cuser)
        return service.authorization_get_all_permission()
