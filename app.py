from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker,declarative_base
from flask import Flask, jsonify, make_response,request
from flask_restful import Api, Resource, reqparse
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
api = Api(app)

# SQLAlchemy configuration
engine = create_engine('sqlite:///users.db')
Session = sessionmaker(bind=engine)
Base = declarative_base()

# User model
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password = Column(String(255))
    permission_level = Column(String(10))

# Create the database tables
Base.metadata.create_all(engine)

# JWT configuration
app.config['JWT_SECRET_KEY'] = 'jwtsecretkey'


def generate_token(user_id, permission_level):
    payload = {
        'user_id': user_id,
        'permission_level': permission_level
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def validate_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

# Authentication and Authorization decorators
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            token = token.split(' ')[1]  # Remove "Bearer " prefix
            payload = validate_token(token)
            if payload and payload['permission_level'] == 'admin':
                return fn(*args, **kwargs)
            else:
                return forbidden_error(None)
        else:
            return missing_token_error(None)
    return wrapper

def user_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            token = token.split(' ')[1]  # Remove "Bearer " prefix
            payload = validate_token(token)
            user_id = kwargs.get('user_id')
            if payload and (payload['permission_level'] == 'user' or payload['user_id'] == user_id):
                return fn(*args, **kwargs)
            else:
                return forbidden_error(None)
        else:
            return missing_token_error(None)
    return wrapper


# User resource
class UserResource(Resource):
    @admin_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('permission_level', type=str, required=True, help='Permission level is required')
        args = parser.parse_args()
        session = Session()
        existing_user = session.query(User).filter_by(username=args['username']).first()
        if existing_user:
            return {'message': 'Username already exists'}, 409
        password_hash = generate_password_hash(args['password'])
        new_user = User(username=args['username'], password=password_hash, permission_level=args['permission_level'])
        session.add(new_user)
        session.commit()
        session.refresh(new_user)
        return {'message': 'User created successfully'},201

    @admin_required
    def delete(self, user_id):
        session = Session()
        user = session.query(User).filter_by(id=user_id).first()
        print(user)
        if user:
            session.delete(user)
            session.commit()
            return {'message': 'User deleted successfully'},204
        else:
            return {'message': 'User not found'}, 404

    @user_required
    def get(self, user_id):
        session = Session()
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            return {
                'id': user.id,
                'username': user.username,
                'permission_level': user.permission_level
            },200
        else:
            return {'message': 'User not found'}, 404

    @admin_required
    def put(self, user_id):
        session = Session()
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            parser = reqparse.RequestParser()
            parser.add_argument('username', type=str, required=True, help='Username is required')
            parser.add_argument('password', type=str, required=False, help='Password is optional')
            parser.add_argument('permission_level', type=str, required=False, help='Permission level is optional')
            args = parser.parse_args()
            user.username = args['username']
            if args['password']:
                user.password = generate_password_hash(args['password'])
            if args['permission_level']:
                user.permission_level = args['permission_level']
            else:
                user.permission_level='user'
            session.commit()
            return {'message': 'User updated successfully'},200
        else:
            return {'message': 'User not found'}, 404

class UserCreationResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('permission_level', type=str, required=True, help='Permission level is required')
        args = parser.parse_args()
        # Check if user with the same username already exists
        session = Session()
        existing_user = session.query(User).filter_by(username=args['username']).first()
        if existing_user:
            return {'message': 'Username already exists'}, 409
        # Create a new user
        hashed_password = generate_password_hash(args['password'])
        user = User(username=args['username'], password=hashed_password, permission_level=args['permission_level'])
        session.add(user)
        session.commit()

        return {'message': 'User created successfully'}, 201


class LoginResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()
        session = Session()
        user = session.query(User).filter_by(username=args['username']).first()
        if user and check_password_hash(user.password, args['password']):
            access_token = generate_token(user_id=user.id, permission_level=user.permission_level)
            return {'access_token': access_token}, 200
        else:
            return {'message': 'Invalid credentials'}, 401

class CreateSampleResource(Resource):
    def get(self):
        admin_data = {"username": "admin", "password": "admin", "permission_level":"admin"}
        user_data={"username": "user", "password": "user", "permission_level":"user"}
        admin_token= generate_token(1, 'admin')
        response_admin= requests.post(f'{request.host_url.rstrip("/")}/users', json=admin_data, headers={'Authorization': f'Bearer {admin_token}'})
        response_user =requests.post(f'{request.host_url.rstrip("/")}/users', json=user_data, headers={'Authorization': f'Bearer {admin_token}'})
        return {
            'admin_response': response_admin.json(),
            'user_response': response_user.json()
        }, 201

# api.add_resource(LoginResource, '/login')
# api.add_resource(UserCreationResource, '/signup')

api.add_resource(CreateSampleResource, '/sample_data')
api.add_resource(UserResource, '/users','/users/<int:user_id>')



# JWT authentication error handler
@app.errorhandler(401)
def missing_token_error(error):
    response = make_response(jsonify({'message': 'Missing authorization token'}))
    response.status_code = 401
    return response

@app.errorhandler(403)
def forbidden_error(error):
    response = make_response(jsonify({'message': 'Insufficient permissions'}))
    response.status_code = 403
    return response

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"message": "Internal server error"}), 500


if __name__ == '__main__':
    app.run(debug=True)
