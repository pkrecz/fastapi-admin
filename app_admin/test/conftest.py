import os
import pytest
import logging
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.database import Base, get_db
from config.registry import init_data
from main import app


engine = create_engine(os.getenv("DATABASE_URL_TEST"))


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    logging.info("Configuration -----> Tables for testing has been created.")
    yield
    Base.metadata.drop_all(bind=engine)
    logging.info("Configuration -----> Tables for testing has been removed.")


@pytest.fixture(scope="session")
def db():
    connection = engine.connect()
    logging.info("Configuration -----> Connection established.")
    transaction = connection.begin()
    logging.info("Configuration -----> Transaction started.")
    session = sessionmaker(
                            autocommit=False,
                            autoflush=False,
                            bind=connection)()
    logging.info("Configuration -----> Session created.")
    init_data(session)
    logging.info("Configuration -----> Initial data have been loaded.")
    logging.info("Configuration -----> Session ready for running.")
    yield session
    session.close()
    logging.info("Configuration -----> Session closed.")
    transaction.rollback()
    logging.info("Configuration -----> Rollback executed.")
    connection.close()
    logging.info("Configuration -----> Connection closed.")


@pytest.fixture(scope="session")
def client(db):

    def override_get_db():
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    logging.info("Configuration -----> Dependency overrided.")
    with TestClient(app) as cli:
        logging.info("Configuration -----> Client ready for running.")
        yield cli
        logging.info("Configuration -----> Client finished job.")


@pytest.fixture()
def data_test_login_as_admin():
    return {
            "username": "root",
            "password": "admin"}


@pytest.fixture()
def data_test_register_user():
    return {
            "username": "test",
            "full_name": "User Test",
            "email": "test@example.com",
            "password": "!ws@test_password",
            "password_confirm": "!ws@test_password"}


@pytest.fixture()
def data_test_login():
    return {
            "username": "test",
            "password": "!ws@test_password"}


@pytest.fixture()
def data_test_update_user():
    return {
            "full_name": "User Test - update",
            "email": "test_update@example.com"}


@pytest.fixture()
def data_test_change_password():
    return {
            "old_password": "!ws@test_password",
            "new_password": "new@test_password",
            "new_password_confirm": "new@test_password"}


@pytest.fixture()
def data_test_create_role():
    return {
            "name": "test_role"}


@pytest.fixture()
def data_test_role_permission():
    return {
            "username": "test",
            "role_name": "test_role",
            "permission_name": "example_permission"}
