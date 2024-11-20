from sqlalchemy import Table, Column, ForeignKey, Integer, String, Boolean, UniqueConstraint
from sqlalchemy.orm import relationship
from config.database import Base


user_role = Table(
    "user_role", Base.metadata,
    Column("user_id", Integer, ForeignKey("user.id")),
    Column("role_id", Integer, ForeignKey("role.id")),
    UniqueConstraint("user_id", "role_id", name="UC_user_role"))

role_permission = Table(
    "role_permission", Base.metadata,
    Column("role_id", Integer, ForeignKey("role.id")),
    Column("permission_id", Integer, ForeignKey("permission.id")),
    UniqueConstraint("role_id", "permission_id", name="UC_role_permission"))


class UserModel(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    full_name = Column(String(100))
    email = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(250), nullable=False)
    is_active = Column(Boolean, default=True)
    roles = relationship("RoleModel", secondary=user_role, back_populates="users")


class RoleModel(Base):
    __tablename__ = "role"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(50), unique=True, index=True, nullable=False)
    users = relationship("UserModel", secondary=user_role, back_populates="roles")
    permissions = relationship("PermissionModel", secondary=role_permission, back_populates="roles")


class PermissionModel(Base):
    __tablename__ = "permission"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    roles = relationship("RoleModel", secondary=role_permission, back_populates="permissions")
