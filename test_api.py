import pytest
from app import app,generate_token

@pytest.fixture
def admin_token():
    # Generate an admin token for testing
    admin_user_id = 1  # ID of the admin user
    admin_permission_level = 'admin'
    return generate_token(admin_user_id, admin_permission_level)

@pytest.fixture
def user_token():
    # Generate a regular user token for testing
    user_id = 2  # ID of a regular user
    user_permission_level = 'user'
    return generate_token(user_id, user_permission_level)

@pytest.fixture
def client():
    # Create a test client using Flask's test_client
    with app.test_client() as client:
        yield client

def test_admin_get_users(client, admin_token):
    # Send a GET request to retrieve users using an admin token
    response = client.get('/users/1', headers={'Authorization': f'Bearer {admin_token}'})
    assert response.status_code == 200
    

def test_admin_create_user(client, admin_token):
    # Send a POST request to create a new user using an admin token
    data = {"username": "John Doe", "password": "john@example", "permission_level":"user"}
    response = client.post('/users', json=data, headers={'Authorization': f'Bearer {admin_token}'})
    assert response.status_code == 201
    

def test_admin_update_user(client, admin_token):
    # Send a PUT request to update a user using an admin token
    user_id = 3  # ID of the user to update
    data = {"username": "Updated Name"}
    response = client.put(f'/users/{user_id}', json=data, headers={'Authorization': f'Bearer {admin_token}'})
    assert response.status_code == 200
    

def test_admin_delete_user(client, admin_token):
    # Send a DELETE request to delete a user using an admin token
    user_id = 3  # ID of the user to delete
    response = client.delete(f'/users/{user_id}', headers={'Authorization': f'Bearer {admin_token}'})
    assert response.status_code == 204
    # Add more assertions or additional requests to validate the deletion

def test_user_get_user(client, user_token):
    # Send a GET request to retrieve user details using a user token
    user_id = 1  # ID of the user to retrieve
    response = client.get(f'/users/{user_id}', headers={'Authorization': f'Bearer {user_token}'})
    assert response.status_code == 200
    

def test_user_create_user(client, user_token):
    # Send a POST request to create a new user using a user token
    data = {"username": "John Doe", "password": "john@example", "permission_level":"user"}
    response = client.post('/users', json=data, headers={'Authorization': f'Bearer {user_token}'})
    assert response.status_code == 403
    assert response.json['message'] == 'Insufficient permissions'
    

def test_user_update_user(client, user_token):
    # Send a PUT request to update a user using a user token
    user_id = 3  # ID of the user to update
    data = {"username": "Updated Name"}
    response = client.put(f'/users/{user_id}', json=data, headers={'Authorization': f'Bearer {user_token}'})
    assert response.status_code == 403
    assert response.json['message'] == 'Insufficient permissions'
    

def test_user_delete_user(client, user_token):
    # Send a DELETE request to delete a user using a user token
    user_id = 3  # ID of the user to delete
    response = client.delete(f'/users/{user_id}', headers={'Authorization': f'Bearer {user_token}'})
    assert response.status_code == 403
    assert response.json['message'] == 'Insufficient permissions'

