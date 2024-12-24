from sqlalchemy import Table, Column, ForeignKey, Integer, String, Boolean, UniqueConstraint
from sqlalchemy.orm import relationship, Mapped, mapped_column
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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(250), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    roles: Mapped[list["RoleModel"]] = relationship("RoleModel", secondary=user_role, back_populates="users")


class RoleModel(Base):
    __tablename__ = "role"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    users: Mapped[list["UserModel"]] = relationship("UserModel", secondary=user_role, back_populates="roles")
    permissions: Mapped[list["PermissionModel"]] = relationship("PermissionModel", secondary=role_permission, back_populates="roles")


class PermissionModel(Base):
    __tablename__ = "permission"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    roles: Mapped[list["RoleModel"]] = relationship("RoleModel", secondary=role_permission, back_populates="permissions")
