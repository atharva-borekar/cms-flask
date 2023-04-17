from flask import request, jsonify
from flask_cors import cross_origin
from werkzeug.security import check_password_hash,generate_password_hash
from flask_jwt_extended import create_access_token, current_user, jwt_required, verify_jwt_in_request
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

from src.app import db

from src.models.ssl_certificate import SSLCertificate
import pdb


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
def add_certificate(user_id):
    try:
        certificate = request.json["certificate"]
        new_cert = SSLCertificate(certificate=certificate, created_by=user_id)
        print(new_cert)
        db.session.add(new_cert)
        db.session.commit()
        return jsonify({
            "message": "Certificate added successfully!",
            "certificate": new_cert.id
        }), 201
    except Exception as e:
        print(e)
        db.session.rollback();
        return jsonify({'message': f'An error occurred while adding certificate: {str(e)}'}), 500

@cross_origin()
def get_certificate(user_id, certificate_id):
    try:
        cert = SSLCertificate.query.filter(SSLCertificate.id == certificate_id, SSLCertificate.created_by == user_id).first()
        print('cert',cert)
        print('cert nva', cert)
        if cert is None:
            return 'Certificate not found', 404
        else:
            if cert.created_by == user_id:
                certificate = x509.load_pem_x509_certificate(cert.certificate.encode(), default_backend())
                expiry_date = certificate.not_valid_after
                return jsonify({'start_date': certificate.not_valid_before, 'expiry_date': expiry_date, "certificate":cert}), 200
            else:
                return 'This certificate is owned by someone else!'
    except Exception as e:
        print(e)
        db.session.rollback();
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500
    
@cross_origin()
def get_certificates(user_id):
    try:
        certificates = SSLCertificate.query.filter(SSLCertificate.created_by == user_id).all()
        if certificates is None:
            return 'No certificates created.', 404
        else:
            print(certificates)
            return jsonify({'data': certificates}), 200
    except Exception as e:
        print(e)
        db.session.rollback();
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500
    
def near_expiry_certificate_util(certificate):
    cert_nva = datetime.fromisoformat(certificate.not_valid_after)
    now = datetime.now()
    diff_days = cert_nva - now;
    print(diff_days)
    if (-1 < diff_days.days < 5):
        return True
    else:
        return False

@cross_origin()
def get_near_expiry_certificates(user_id):
    try:
        certificates = SSLCertificate.query.filter(SSLCertificate.created_by == user_id).all()
        if certificates is None:
            return 'No certificates created.', 404
        else:
            near_expiry_certificates = list(filter(near_expiry_certificate_util, certificates))
            print(near_expiry_certificates)
            return jsonify({'data': near_expiry_certificates}), 200
    except Exception as e:
        print(e)
        db.session.rollback();
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500

def expired_certificates_util(certificate):
    cert_nva = datetime.fromisoformat(certificate.not_valid_after)
    now = datetime.now()
    diff_days = cert_nva - now;
    if (diff_days.total_seconds() < 0):
        return True
    else:
        return False

@cross_origin()
def get_expired_certificates(user_id):
    try:
        certificates = SSLCertificate.query.filter(SSLCertificate.created_by == user_id).all()
        if certificates is None:
            return jsonify({'data': []}), 200
        else:
            expired_certificates = list(filter(expired_certificates_util, certificates))
            return jsonify({'data': expired_certificates}), 200
    except Exception as e:
        print(e)
        db.session.rollback();
        return jsonify({'message': f'An error occurred while extracting certificate: {str(e)}'}), 500