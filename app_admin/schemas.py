from pydantic import BaseModel, EmailStr
from typing import Optional


# Schemas for users
class UserBase(BaseModel):
    username: str

    
class UserViewBase(BaseModel):
    id: int
    username: str
    full_name: str
    email: EmailStr
    is_active: bool


class UserCreateBase(BaseModel):
    username: str
    full_name: str
    email: EmailStr
    password: str
    password_confirm: str


class UserUpdateBase(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None

class UserChangePasswordBase(BaseModel):
    old_password: str
    new_password: str
    new_password_confirm: str


# Schemas for token
class TokenAccessRefreshBase(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenAccessBase(BaseModel):
    access_token: str
    token_type: str = "bearer"


# Schemas for roles
class RoleBase(BaseModel):
    name: str


class UserWithRoleBase(BaseModel):
    id: int
    username: str
    roles: list[RoleBase]

    class Config:
        from_attributes = True
        json_encoders = {RoleBase: lambda v: v.name}


class RoleWithUserBase(BaseModel):
    name: str
    users: list[UserBase]

    class Config:
        from_attributes = True
        json_encoders = {UserBase: lambda v: v.username}


# Schemas for permissions
class PermissionBase(BaseModel):
    name: str


class RoleWithPermissionsBase(BaseModel):
    name: str
    permissions: list[PermissionBase]


class UserWithPermissionBase(BaseModel):
    id: int
    username: str
    roles: list[RoleWithPermissionsBase]
