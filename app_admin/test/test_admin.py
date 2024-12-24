import os
import logging


def sub_test_register_user(
                                client,
                                data_test_register_user):
    response = client.post(
                                url=f"/admin/register/",
                                json=data_test_register_user,
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Register user testing ...")
    assert response.status_code == 201
    assert response_json["username"] == data_test_register_user["username"]
    assert response_json["full_name"] == data_test_register_user["full_name"]
    assert response_json["email"] == data_test_register_user["email"]
    assert response_json["is_active"] == True
    logging.info("Register user testing finished.")


def sub_test_login(
                                client,
                                data_test_login):
    response = client.post(
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
                                client,
                                data_test_update_user):
    response = client.put(
                                url=f"/admin/update/",
                                json=data_test_update_user,
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Update user testing ...")
    assert response.status_code == 200
    assert response_json["full_name"] == data_test_update_user["full_name"]
    assert response_json["email"] == data_test_update_user["email"]
    logging.info("Update user testing finished.")


def sub_test_change_password(
                                client,
                                data_test_change_password):
    response = client.put(
                                url=f"/admin/change_password/",
                                json=data_test_change_password,
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Changing password testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Password changed successfully."}
    logging.info("Changing password testing finished.")


def sub_test_refresh(client):
    response = client.post(
                                url=f"/admin/refresh/",
                                headers={"Authorization": f"Bearer {os.environ["REFRESH_TOKEN"]}"})
    response_json = response.json()
    logging.info("Refresh token testing ...")
    assert response.status_code == 200
    assert response_json["access_token"] is not None
    logging.info("Refresh token testing finished.")
    os.environ["BEARER_TOKEN"] = response_json["access_token"]


def sub_test_delete_user(client):
    response = client.delete(
                                url=f"/admin/delete/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Deletion user testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "User deleted successfully."}
    logging.info("Deletion user testing finished.")


def sub_test_create_role(
                                client,
                                data_test_create_role):
    response = client.post(
                                url=f"/admin/create_role/",
                                json=data_test_create_role,
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Creation role testing ...")
    assert response.status_code == 201
    assert response_json["name"] == data_test_create_role["name"]
    logging.info("Creation role testing finished.")


def sub_test_assign_role(
                                client,
                                data_test_role_permission):
    username = data_test_role_permission["username"]
    role = data_test_role_permission["role_name"]
    response = client.post(
                                url=f"/admin/assign_role/{username}/role/{role}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Assign role to user testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Role assigned to user."}
    logging.info("Assign role to user testing finished.")


def sub_test_get_role_per_user(
                                client,
                                data_test_role_permission):
    username = data_test_role_permission["username"]
    response = client.get(
                                url=f"/admin/role_per_user/{username}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    logging.info("Get role per user testing ...")
    assert response.status_code == 200
    logging.info("Get role per user testing finished.")


def sub_test_get_user_per_role(
                                client,
                                data_test_role_permission):
    role = data_test_role_permission["role_name"]
    response = client.get(
                                url=f"/admin/user_per_role/{role}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    logging.info("Get user per role testing ...")
    assert response.status_code == 200
    logging.info("Get user per role testing finished.")


def sub_test_get_permission_per_user(
                                client,
                                data_test_role_permission):
    username = data_test_role_permission["username"]
    response = client.get(
                                url=f"/admin/permission_per_user/{username}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    logging.info("Get permission per user testing ...")
    assert response.status_code == 200
    logging.info("Get permission per user testing finished.")


def sub_test_get_all_permission(client):
    response = client.get(
                                url=f"/admin/permission_all/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    logging.info("Get all permission testing ...")
    assert response.status_code == 200
    logging.info("Get all permission testing finished.")


def sub_test_unassign_role(
                                client,
                                data_test_role_permission):
    username = data_test_role_permission["username"]
    role = data_test_role_permission["role_name"]
    response = client.post(
                                url=f"/admin/unassign_role/{username}/role/{role}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Unassign role to user testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Role unassigned from user."}
    logging.info("Unassign role to user testing finished.")


def sub_test_assign_permission(
                                client,
                                data_test_role_permission):
    role = data_test_role_permission["role_name"]
    permission = data_test_role_permission["permission_name"]
    response = client.post(
                                url=f"/admin/assign_permission/{role}/permission/{permission}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Assign permission to role testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Permission assigned to role."}
    logging.info("Assign permission to role testing finished.")


def sub_test_unassign_permission(
                                client,
                                data_test_role_permission):
    role = data_test_role_permission["role_name"]
    permission = data_test_role_permission["permission_name"]
    response = client.post(
                                url=f"/admin/unassign_permission/{role}/permission/{permission}/",
                                headers={"Authorization": f"Bearer {os.environ["BEARER_TOKEN"]}"})
    response_json = response.json()
    logging.info("Unassign permission from role testing ...")
    assert response.status_code == 200
    assert response_json == {"message": "Permission unassigned from role."}
    logging.info("Unassign permission from role testing finished.")


def test_authentication(
                client,
                data_test_login_as_admin,
                data_test_register_user,
                data_test_login,
                data_test_update_user,
                data_test_change_password):
    logging.info("START - testing authentication module")
    sub_test_login(client, data_test_login_as_admin)
    sub_test_register_user(client, data_test_register_user)
    sub_test_refresh(client)
    sub_test_login(client, data_test_login)
    sub_test_update_user(client, data_test_update_user)
    sub_test_change_password(client, data_test_change_password)
    sub_test_delete_user(client)
    logging.info("STOP - testing authentication module")


def test_authorization(
                client,
                data_test_login_as_admin,
                data_test_register_user,
                data_test_create_role,
                data_test_role_permission):
    logging.info("START - testing authorization module")
    sub_test_login(client, data_test_login_as_admin)
    sub_test_create_role(client, data_test_create_role)
    sub_test_register_user(client, data_test_register_user)
    sub_test_assign_role(client, data_test_role_permission)
    sub_test_assign_permission(client, data_test_role_permission)
    sub_test_get_role_per_user(client, data_test_role_permission)
    sub_test_get_user_per_role(client, data_test_role_permission)
    sub_test_get_permission_per_user(client, data_test_role_permission)
    sub_test_get_all_permission(client)
    sub_test_unassign_role(client, data_test_role_permission)
    sub_test_unassign_permission(client, data_test_role_permission)
    logging.info("STOP - testing authorization module")
