from datetime import datetime

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


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
            "dob": new_user.dob,
            "gender": new_user.gender,
            "email": new_user.email
        }
    }), 201


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)