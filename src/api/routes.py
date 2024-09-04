"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
import hashlib
from flask_jwt_extended import create_access_token, get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

def get_hash(string):
    return hashlib.sha256(bytes(string, 'utf-8')).hexdigest()

@api.route('/signup', methods=['POST'])
def create_user():
    email = request.json.get("email")
    password = request.json.get("password")
    secure_password = get_hash(
        password)
    
    new_user = User()
    new_user.email = email
    new_user.password = secure_password
    new_user.is_active = True
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "Congrats! User created."}), 201

@api.route('/login', methods=['POST'])
def login_user():
  
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    
    found_user = User.query.filter_by(email=email, password=get_hash(password)).one_or_none()

    if found_user is None:
        return "Your email or password are incorrect.", 400
    
    token = create_access_token(identity=email)
    return jsonify(token=token)

@api.route("/private", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200