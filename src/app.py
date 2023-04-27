from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token
import os
from flask_migrate import Migrate

from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/flaskpoc'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'abcd1234')
app.config['JWT_HEADER_TYPE'] = False

db = SQLAlchemy(app)
Migrate(app, db)

with app.app_context():
    db.create_all()
jwt = JWTManager(app)

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    from src.models.user import User
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

def app_factory():
    from src.views.auth import (
        signInUser,
        signUpUser,
        home
    )
    from src.views.ssl_certificate import (
        add_certificate, 
        get_certificate, 
        get_certificates, 
        get_expired_certificates, 
        get_near_expiry_certificates,
        create_certificate,
        download_certificate,
        renew_certificate,
        generate_csr,
        sign_csr,
        download_private_key
    )
    app.add_url_rule('/home', view_func=home, methods=['GET'])
    app.add_url_rule('/users/signup', view_func=signUpUser, methods=['POST'])
    app.add_url_rule('/users/signin', view_func=signInUser, methods=['POST'])
    app.add_url_rule('/users/<int:user_id>/add_certificate', view_func=add_certificate, methods=['POST'])
    app.add_url_rule('/users/<int:user_id>/create_certificate', view_func=create_certificate, methods=['POST'])
    app.add_url_rule('/users/<int:user_id>/get_certificate/<int:certificate_id>', view_func=get_certificate, methods=['GET'])
    app.add_url_rule('/users/<int:user_id>/get_certificates', view_func=get_certificates, methods=['GET'])
    app.add_url_rule('/users/<int:user_id>/get_expired_certificates', view_func=get_expired_certificates, methods=['GET'])
    app.add_url_rule('/users/<int:user_id>/get_near_expiry_certificates', view_func=get_near_expiry_certificates, methods=['GET'])
    app.add_url_rule('/users/<int:user_id>/download_certificate/<int:certificate_id>', view_func=download_certificate, methods=['GET'])
    app.add_url_rule('/users/<int:user_id>/renew_certificate/<int:certificate_id>', view_func=renew_certificate, methods=['POST'])
    app.add_url_rule('/generate_csr', view_func=generate_csr, methods=['POST'])
    app.add_url_rule('/sign_csr', view_func=sign_csr, methods=['POST'])
    app.add_url_rule('/users/<int:user_id>/download_private_key/<int:certificate_id>', view_func=download_private_key, methods=['POST'])
    return app
