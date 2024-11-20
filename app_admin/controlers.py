from fastapi import APIRouter, status, Depends
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from config.database import get_db
from . import exceptions
from .repository import repo_functions, repo_dependency
from .schemas import (UserCreateBase, UserViewBase, UserUpdateBase, UserChangePasswordBase,
                      TokenAccessRefreshBase, TokenAccessBase,
                      RoleBase, UserWithRoleBase, RoleWithUserBase, UserWithPermissionBase, PermissionBase)
from .models import UserModel, RoleModel, PermissionModel
from .decorators import permission_required


router_user = APIRouter()
router_role = APIRouter()
router_nolog = APIRouter()


req_perm_api_list = ["user_show", "user_register", "user_update", "user_delete", "user_change_password",
                     "role_create", "role_assign", "role_unassign", "role_per_user", "user_per_role",
                     "permission_assign", "permission_unassign", "permission_per_user", "permission_all"]


#  API for users
@router_user.get(path="/show/{username}/", status_code=status.HTTP_200_OK, response_model=UserViewBase)
@permission_required(required_permission="user_show")
async def show_user(
                        username: str,
                        db: Session = Depends(get_db),
                        current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        user_query = repo_functions.query_get_user_by_username(db, username)
        if user_query.count() == 0:
            raise exceptions.UserNotFoundException
        return user_query.first()
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_nolog.post(path="/register/", status_code=status.HTTP_201_CREATED, response_model=UserViewBase)
@permission_required(required_permission="user_register")
async def register_user(
                        input_data: UserCreateBase,
                        db: Session = Depends(get_db),
                        current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        user_query = repo_functions.query_get_user_by_username(db, input_data.username)
        if user_query.count() == 1:
            raise exceptions.UserExistsException
        user_query = repo_functions.query_get_user_by_email(db, input_data.email)
        if user_query.count() == 1:
            raise exceptions.EmailExistsException
        if repo_functions.check_the_same_password(input_data.password, input_data.password_confirm) == False:
            raise exceptions.NotTheSamePasswordException
        data = {
            "username": input_data.username,
            "full_name": input_data.full_name,
            "email": input_data.email,
            "hashed_password": repo_functions.hash_password(input_data.password)}
        instance = UserModel(**data)
        db.add(instance)
        db.commit()
        db.refresh(instance)
        return instance
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_user.put(path="/update/{username}/", status_code=status.HTTP_200_OK, response_model=UserViewBase)
@permission_required(required_permission="user_update")
async def update_user(
                        username: str,
                        input_data: UserUpdateBase,
                        db: Session = Depends(get_db),
                        current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        user_query = repo_functions.query_get_user_by_username(db, username)
        if user_query.count() == 0:
            raise exceptions.UserNotFoundException
        user_query.update(input_data.model_dump(exclude_unset=True))
        db.commit()
        return user_query.first()
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_user.delete(path="/delete/{username}/", status_code=status.HTTP_200_OK)
@permission_required(required_permission="user_delete")
async def delete_user(
                        username: str,
                        db: Session = Depends(get_db),
                        current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        user_query = repo_functions.query_get_user_by_username(db, username)
        if user_query.count() == 0:
            raise exceptions.UserNotFoundException
        db.delete(user_query.first())
        db.commit()
        return JSONResponse(content={"message": "User deleted successfully."}, status_code=status.HTTP_200_OK)
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_user.put(path="/change_password/{username}/", status_code=status.HTTP_200_OK)
@permission_required(required_permission="user_change_password")
async def change_password(
                            username: str,
                            input_data: UserChangePasswordBase,
                            db: Session = Depends(get_db),
                            current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        user_query = repo_functions.query_get_user_by_username(db, username)
        if user_query.count() == 0:
            raise exceptions.UserNotFoundException
        if repo_functions.check_the_same_password(input_data.new_password, input_data.new_password_confirm) == False:
            raise exceptions.NotTheSamePasswordException
        if repo_functions.verify_password(input_data.old_password, user_query.first().hashed_password) == False:
            raise exceptions.IncorrectPasswordException
        user_query.update({"hashed_password": repo_functions.hash_password(input_data.new_password)})
        db.commit()
        return JSONResponse(content={"message": "Password changed successfully."}, status_code=status.HTTP_200_OK)
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_nolog.post(path="/login/", status_code=status.HTTP_200_OK, response_model=TokenAccessRefreshBase)
async def login(
                    form_data: OAuth2PasswordRequestForm = Depends(),
                    db: Session = Depends(get_db)):
    try:
        user = repo_functions.authenticate_user(db, form_data.username, form_data.password)
        if not user:
            raise exceptions.CredentialsException
        if repo_functions.get_active_status(db, user.username) == False:
            raise exceptions.UserInActiveException
        access_token = repo_functions.create_token(data={"sub": user.username}, refresh=False)
        refresh_token = repo_functions.create_token(data={"sub": user.username}, refresh=True)
        return JSONResponse(content={"access_token": access_token, "refresh_token": refresh_token}, status_code=status.HTTP_200_OK)
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_nolog.post(path="/refresh/", status_code=status.HTTP_200_OK, response_model=TokenAccessBase)
async def refresh(user: UserModel = Depends(repo_dependency.refresh_token_dependency)):
    try:
        access_token = repo_functions.create_token(data={"sub": user.username}, refresh=False)
        return JSONResponse(content={"access_token": access_token}, status_code=status.HTTP_200_OK)
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


#  API for roles
@router_role.post(path="/create_role/", status_code=status.HTTP_201_CREATED, response_model=RoleBase)
@permission_required(required_permission="role_create")
async def create_role(
                        input_data: RoleBase,
                        db: Session = Depends(get_db),
                        current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        role_query = repo_functions.query_get_role_by_name(db, input_data.name)
        if role_query.count() != 0:
            raise exceptions.BadRequestException("Role already exists.")
        instance = RoleModel(**input_data.model_dump())
        db.add(instance)
        db.commit()
        db.refresh(instance)
        return instance
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_role.post(path="/assign_role/{username}/role/{role_name}/", status_code=status.HTTP_200_OK)
@permission_required(required_permission="role_assign")
async def assign_role_to_user(
                                username: str,
                                role_name: str,
                                db: Session = Depends(get_db),
                                current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        user_query = repo_functions.query_get_user_by_username(db, username)
        role_query = repo_functions.query_get_role_by_name(db, role_name)
        if user_query.count() == 0 or role_query.count() == 0:
            raise exceptions.NotFoundException("User or role was not found.")
        try:
            queue = user_query.first()
            queue.roles.append(role_query.first())
            db.commit()
        except:
            raise exceptions.BadRequestException("Assigment already exists.")
        return JSONResponse(content={"message": "Role assigned to user."}, status_code=status.HTTP_200_OK)
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_role.post(path="/unassign_role/{username}/role/{role_name}/", status_code=status.HTTP_200_OK)
@permission_required(required_permission="role_unassign")
async def unassign_role_from_user(
                                username: str,
                                role_name: str,
                                db: Session = Depends(get_db),
                                current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        user_query = repo_functions.query_get_user_by_username(db, username)
        role_query = repo_functions.query_get_role_by_name(db, role_name)
        if user_query.count() == 0 or role_query.count() == 0:
            raise exceptions.NotFoundException("User or role was not found.")
        try:
            queue = user_query.first()
            queue.roles.remove(role_query.first())    
            db.commit()
        except:
            raise exceptions.BadRequestException("Assigment was not found.")
        return JSONResponse(content={"message": "Role unassigned from user."}, status_code=status.HTTP_200_OK)
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_role.get(path="/role_per_user/{username}/", status_code=status.HTTP_200_OK, response_model=UserWithRoleBase)
@permission_required(required_permission="role_per_user")
async def show_role_per_user(
                                username: str,
                                db: Session = Depends(get_db),
                                current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        user_query = repo_functions.query_get_user_by_username(db, username)
        if user_query.count() == 0:
            raise exceptions.UserNotFoundException
        return user_query.first()
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_role.get(path="/user_per_role/{role_name}/", status_code=status.HTTP_200_OK, response_model=RoleWithUserBase)
@permission_required(required_permission="user_per_role")
async def show_user_per_role(
                                role_name: str,
                                db: Session = Depends(get_db),
                                current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        role_query = repo_functions.query_get_role_by_name(db, role_name)
        if role_query.count() == 0:
            raise exceptions.NotFoundException("Role was not found.")
        return role_query.first()
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


# API for permissions
@router_role.post(path="/assign_permission/{role_name}/permission/{permission_name}/", status_code=status.HTTP_200_OK)
@permission_required(required_permission="permission_assign")
async def assign_permission_to_role(
                                    role_name: str,
                                    permission_name: str,
                                    db: Session = Depends(get_db),
                                    current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        role_query = repo_functions.query_get_role_by_name(db, role_name)
        permission_query = repo_functions.query_get_permission_by_name(db, permission_name)
        if role_query.count() == 0 or permission_query.count() == 0:
            raise exceptions.NotFoundException("Role or permission was not found.")
        try:
            queue = role_query.first()
            queue.permissions.append(permission_query.first())
            db.commit()
        except:
            raise exceptions.BadRequestException("Assigment already exists.")
        return JSONResponse(content={"message": "Permission assigned to role."}, status_code=status.HTTP_200_OK)
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_role.post(path="/unassign_permission/{role_name}/permission/{permission_name}/", status_code=status.HTTP_200_OK)
@permission_required(required_permission="permission_unassign")
async def unassign_permission_from_role(
                                    role_name: str,
                                    permission_name: str,
                                    db: Session = Depends(get_db),
                                    current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        role_query = repo_functions.query_get_role_by_name(db, role_name)
        permission_query = repo_functions.query_get_permission_by_name(db, permission_name)
        if role_query.count() == 0 or permission_query.count() == 0:
            raise exceptions.NotFoundException("Role or permission was not found.")
        try:
            queue = role_query.first()
            queue.permissions.remove(permission_query.first())
            db.commit()
        except:
            raise exceptions.BadRequestException("Assigment was not found.")
        return JSONResponse(content={"message": "Permission unassigned from role."}, status_code=status.HTTP_200_OK)
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_role.get(path="/permission_per_user/{username}/", status_code=status.HTTP_200_OK, response_model=UserWithPermissionBase)
@permission_required(required_permission="permission_per_user")
async def show_permissions_per_user(
                                    username: str,
                                    db: Session = Depends(get_db),
                                    current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        user_query = repo_functions.query_get_user_by_username(db, username)
        if user_query.count() == 0:
            raise exceptions.UserNotFoundException
        return user_query.first()
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)


@router_role.get(path="/permission_all/", status_code=status.HTTP_200_OK, response_model=list[PermissionBase])
@permission_required(required_permission="permission_all")
async def show_all_permissions(
                                db: Session = Depends(get_db),
                                current_user: UserModel = Depends(repo_dependency.log_dependency)):
    try:
        permission_query = db.query(PermissionModel)
        if permission_query.count() == 0:
            raise exceptions.BadRequestException("No permission found.")
        return permission_query.all()
    except Exception as exception:
        return JSONResponse(content={"detail": exception.detail}, status_code=exception.status_code)
