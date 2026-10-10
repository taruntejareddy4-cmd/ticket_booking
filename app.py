import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from functools import wraps
from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY")

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mysql+pymysql://root:@localhost:3306/ticket_booking"
)

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

class Movie(db.Model):
    __tablename__ = "movies"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    genre = db.Column(db.String(50))


class Theatre(db.Model):
    __tablename__ = "theatres"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)


class Screen(db.Model):
    __tablename__ = "screens"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    theatre_id = db.Column(db.Integer, db.ForeignKey("theatres.id"), nullable=False)


class Show(db.Model):
    __tablename__ = "shows"

    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey("movies.id"), nullable=False)
    screen_id = db.Column(db.Integer, db.ForeignKey("screens.id"), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    price = db.Column(db.Numeric(8, 2), nullable=False)


@app.route("/")
def hello():
    return jsonify({"status": "ok"})


# POST API for registering a user
@app.route("/users", methods=["POST"])
def create_user():

    data = request.get_json()

    if not data:
        return jsonify({"error": "JSON data is required"}), 400

    name = data.get("name")
    dob = data.get("dob")
    gender = data.get("gender")
    email = data.get("email")
    password = data.get("password")

    if not name:
        return jsonify({"error": "Name is required"}), 400

    if not dob:
        return jsonify({"error": "Date of Birth is required"}), 400

    try:
        dob = datetime.strptime(dob, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return jsonify({"error": "dob must be in YYYY-MM-DD format"}), 400

    if not gender:
        return jsonify({"error": "Gender is required"}), 400

    if not email:
        return jsonify({"error": "Email is required"}), 400

    if not password:
        return jsonify({"error": "Password is required"}), 400

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({"error": "Email already exists"}), 409

    hashed_password = generate_password_hash(password)

    new_user = User(
        name=name,
        dob=dob,
        gender=gender,
        email=email,
        password_hash=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "User registered successfully",
        "user": {
            "id": new_user.id,
            "name": new_user.name,
            "dob": new_user.dob.isoformat(),
            "gender": new_user.gender,
            "email": new_user.email
        }
    }), 201


# POST API for login
@app.route("/login", methods=["POST"])
def login():
    request_data = request.get_json(silent=True) or {}
    email = request_data.get("email")
    password = request_data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    found_user = User.query.filter_by(email=email).first()
    if found_user is None or not check_password_hash(found_user.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401

    payload = {
        "sub": str(found_user.id),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({"token": token, "name": found_user.name}), 200

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "token is missing or malformed"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        found_user = User.query.filter_by(id=int(payload["sub"])).first()
        if found_user is None:
            return jsonify({"error": "user not found"}), 401

        g.user = found_user
        return f(*args, **kwargs)

    return wrapper


@app.route("/me", methods=["GET"])
@login_required
def me():
    return jsonify({
        "id": g.user.id,
        "name": g.user.name,
        "email": g.user.email,
        "dob": g.user.dob.isoformat(),
        "gender": g.user.gender,
    }), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)