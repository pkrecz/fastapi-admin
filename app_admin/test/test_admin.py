import os
import logging
from config.settings import settings
from config import registry


# Subtests for user
def sub_test_register_user(
                                client_test,
                                data_test_register_user):
    response = client_test.post(
                                url=f"/admin/register/",
                                json=data_test_register_user,
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Register user testing ...")
    assert response.status_code == 201
    assert response_json["username"] == "test"
    assert response_json["full_name"] == "User Test"
    assert response_json["email"] == "test@example.com"
    assert response_json["is_active"] == True
    logging.info("Register user testing finished.")


def sub_test_login(
                                client_test,
                                data_test_login):
    response = client_test.post(
                                url=f"/admin/login/",
                                data=data_test_login)
    response_json = response.json()
    logging.info("Login user testing ...")
    assert response.status_code == 200
    assert response_json["access_token"] is not None
    assert response_json["refresh_token"] is not None
    logging.info('Login user testing finished.')
    os.environ["BEARER_TOKEN"] = response_json["access_token"]
    os.environ["REFRESH_TOKEN"] = response_json["refresh_token"]


def sub_test_update_user(
                                client_test,
                                user_name,
                                data_test_update_user):
    response = client_test.put(
                                url=f"/admin/update/{user_name}/",
                                json=data_test_update_user,
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Update user testing ...")
    assert response.status_code == 200
    assert response_json["full_name"] == "User Test - update"
    assert response_json["email"] == "test_update@example.com"
    logging.info("Update user testing finished.")


def sub_test_change_password(
                                client_test,
                                user_name,
                                data_test_change_password):
    response = client_test.put(
                                url=f"/admin/change_password/{user_name}/",
                                json=data_test_change_password,
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Changing password testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Password changed successfully."}
    logging.info("Changing password testing finished.")


def sub_test_refresh(
                                client_test):
    response = client_test.post(
                                url=f"/admin/refresh/",
                                headers={"Authorization": f"Bearer {os.environ["REFRESH_TOKEN"]}"})
    response_json = response.json()
    logging.info("Refresh token testing ...")
    assert response.status_code == 200
    assert response_json["access_token"] is not None
    logging.info("Refresh token testing finished.")
    os.environ["BEARER_TOKEN"] = response_json["access_token"]


def sub_test_delete_user(
                                client_test,
                                user_name):
    response = client_test.delete(
                                url=f"/admin/delete/{user_name}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Deletion user testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "User deleted successfully."}
    logging.info("Deletion user testing finished.")


def sub_test_create_role(
                                client_test,
                                data_test_create_role):
    response = client_test.post(
                                url=f"/admin/create_role/",
                                json=data_test_create_role,
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Creation role testing ...")
    assert response.status_code == 201
    assert response_json["name"] == "test_role"
    logging.info("Creation role testing finished.")


def sub_test_assign_role(
                                client_test,
                                user_name,
                                role_name):
    response = client_test.post(
                                url=f"/admin/assign_role/{user_name}/role/{role_name}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Assign role to user testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Role assigned to user."}
    logging.info("Assign role to user testing finished.")


def sub_test_unassign_role(
                                client_test,
                                user_name,
                                role_name):
    response = client_test.post(
                                url=f"/admin/unassign_role/{user_name}/role/{role_name}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Unassign role to user testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Role unassigned from user."}
    logging.info("Unassign role to user testing finished.")


def sub_test_assign_permission(
                                client_test,
                                role_name,
                                permission_name):
    response = client_test.post(
                                url=f"/admin/assign_permission/{role_name}/permission/{permission_name}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Assign permission to role testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Permission assigned to role."}
    logging.info("Assign permission to role testing finished.")


def sub_test_unassign_permission(
                                client_test,
                                role_name,
                                permission_name):
    response = client_test.post(
                                url=f"/admin/unassign_permission/{role_name}/permission/{permission_name}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Unassign permission from role testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Permission unassigned from role."}
    logging.info("Unassign permission from role testing finished.")


# Test to be performed
def test_overall(
                client_test,
                data_test_login_as_admin,
                data_test_register_user,
                data_test_login,
                data_test_update_user,
                data_test_change_password,
                data_test_create_role):
    logging.info("START - testing admin module")
    registry.create_admin_user(settings.ADMIN_USER_NAME)
    registry.assign_role_to_admin_user(settings.ADMIN_USER_NAME)
    sub_test_login(client_test, data_test_login_as_admin)
    sub_test_register_user(client_test, data_test_register_user)
    sub_test_update_user(client_test, "test", data_test_update_user)
    sub_test_change_password(client_test, "test", data_test_change_password)
    sub_test_create_role(client_test, data_test_create_role)
    sub_test_assign_role(client_test, "test", "test_role")
    sub_test_unassign_role(client_test, "test", "test_role")
    sub_test_assign_permission(client_test, "test_role", "user_show")
    sub_test_unassign_permission(client_test, "test_role", "user_show")
    sub_test_assign_role(client_test, "test", "admin")
    sub_test_login(client_test, data_test_login)
    sub_test_refresh(client_test)
    sub_test_delete_user(client_test, "test")
    logging.info("STOP - testing admin module")
