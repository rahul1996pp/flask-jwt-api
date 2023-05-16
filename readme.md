# API Documentation

This is the documentation for the API endpoints provided by the application.

## Authentication

The API endpoints require authentication using JSON Web Tokens (JWT). To access the protected endpoints, you need to include the JWT token in the `Authorization` header of the HTTP requests.

## Endpoints

### User Resource

#### Create Mock Data

- URL: `/sample_data`
- Method: `GET`
- Description: Create admin and user profiles into database.


#### Get User Details

- URL: `/users/<user_id>`
- Method: `GET`
- Description: Retrieves the details of a specific user.
- Authentication: Required (Admin or User token)
- Permissions:
  - Admin: Can access any user's details.
  - User: Can access only their own details.
- Response Payload:
  ```json
  {
    "id": 1,
    "username": "john",
    "permission_level": "user"
  }

#### Create User

- URL: `/users`
- Method: `POST`
- Description: Creates a new user.
- Authentication: Required (Admin token)
- Permissions: Admin
- Request Payload:
  ```json
  {
  "username": "johndoe",
  "password": "password123",
  "permission_level": "user"
  }

- Response Payload:
  ```json
  {
  "message": "User created successfully"
  }


#### Update User

- URL: `/users/<user_id>`
- Method: `PUT`
- Description: Updates the details of a specific user.
- Authentication: Required (Admin token)
- Permissions: Admin
- Request Payload:
  ```json
  {
  "username": "newusername",
  "password": "newpassword",
  "permission_level": "admin"
  }


- Response Payload:
  ```json
  {
  "message": "User updated successfully"
  }


#### Delete User

- URL: `/users/<user_id>`
- Method: `DELETE`
- Description: Deletes a specific user.
- Authentication: Required (Admin token)
- Permissions: Admin
- Response Payload:
  ```json
  {
  "message": "User deleted successfully"
  }


## Error Handling

The API endpoints return appropriate HTTP status codes and error messages in case of errors. Here are some common error scenarios:

- 401 Unauthorized: Missing or invalid authentication token.
- 403 Forbidden: Insufficient permissions to access the resource.
- 404 Not Found: The requested resource was not found.


## Testing

The API includes unit tests written using pytest, a popular testing framework for Python. You can run the tests to ensure the API functions correctly and handles different scenarios.

To run the tests:

1. Install Poetry by following the instructions at [https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation).
2. Install the project dependencies by running `poetry install`.
3. Execute the command `poetry run pytest` in the project directory.
4. pytest will discover and run all the test cases in the `tests` directory.

Make sure to update the tests in the `tests` directory to match your API endpoints and test scenarios.

## Dependencies

The API is built using the following dependencies:

- Flask: A lightweight web framework for building RESTful APIs.
- Flask-RESTful: An extension for Flask that simplifies building RESTful APIs.
- SQLAlchemy: A SQL toolkit and Object-Relational Mapping (ORM) library.
- PyJWT: A Python library for encoding and decoding JSON Web Tokens (JWT).
- Pytest: A testing framework for Python.
- Other dependencies as specified in the `pyproject.toml` file.

## Usage

1. Install Poetry by following the instructions at [https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation).
2. Clone the project repository.
3. Navigate to the project directory.
4. Install the project dependencies by running `poetry install`.
5. Start the application by running `poetry run python app.py`.
6. The API will be available at `http://localhost:5000`.
7. Make get request to `http://localhost:5000/sample_data` to create admin,user data into database.