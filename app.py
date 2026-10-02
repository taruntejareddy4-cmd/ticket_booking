from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
import jwt

SECRET_KEY = "taruntejareddynagadinesh"

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:@localhost:3306/ticket_booking"

db = SQLAlchemy(app)

class user (db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(255), unique = True, nullable = False)
    password_hash = db.Column(db.String(255), nullable = False)
    created_at = db.Column(db.DateTime, default = datetime.utcnow)

@app.route("/")
def hello():
    return jsonify({"status": "ok"})

@app.route("/login", methods=["POST"])
def login():
    request_data = request.get_json()
    email = request_data.get("email")
    password = request_data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    users = user.query.filter_by(email=email).first()
    if users is None or not check_password_hash(users.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401
    else:
        return jsonify({"message": "login successful"}), 200

    payload = {
        "sub": str(users.id),
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({"token": token}), 200
    


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)




