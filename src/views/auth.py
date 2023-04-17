from flask import request, jsonify
from flask_cors import cross_origin
from werkzeug.security import check_password_hash,generate_password_hash
from flask_jwt_extended import create_access_token, current_user, jwt_required, verify_jwt_in_request

from src.app import db

from src.models.user import User


@jwt_required()
def home():
    try:
        return jsonify({
            "message": "Home page",
        }), 200
    except Exception as e:
        db.session.rollback();
        return jsonify({'message': f'An error occurred while accessing home: {str(e)}'}), 500

@cross_origin()
def signUpUser():
    try:
        request_data = request.json
        new_user = User(name=request_data['name'], username=request_data['username'], password=generate_password_hash(request_data['password']))
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            "message": "User created successfully!"
        }), 201
    except Exception as e:
        print(e)
        db.session.rollback();
        return jsonify({'message': f'An error occurred while creating the user: {str(e)}'}), 500

@cross_origin()
def signInUser():
    try:
        request_data = request.json
        username = request_data["username"]
        password = request_data["password"]
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400
        
        user = User.query.filter(User.username == username).first();
        print(user)
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            return jsonify({'access_token':access_token, 'user': user}),200
        else:
            return jsonify({'error':"Invalid credentials!"}), 401
    except Exception as e:
        db.session.rollback();
        print(str(e))
        return jsonify({'error': f'An error occurred while signing in: {str(e)}'}), 500

