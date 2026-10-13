
# IMPORTS: Import required libraries and functions
import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from functools import wraps
from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


# ENVIRONMENT CONFIGURATION: Load the secret key from the .env file
load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY")


# FLASK APPLICATION: Create the Flask application
app = Flask(__name__)


# DATABASE CONNECTION: Connect Flask to the MySQL database
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mysql+pymysql://root:@localhost:3306/ticket_booking"
)

db = SQLAlchemy(app)


# USER MODEL: Define the users table and its columns
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


# MOVIE MODEL: Define the movies table
class Movie(db.Model):
    __tablename__ = "movies"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    genre = db.Column(db.String(50))


# THEATRE MODEL: Define the theatres table
class Theatre(db.Model):
    __tablename__ = "theatres"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)


# SCREEN MODEL: Define the screens table and link each screen to a theatre
class Screen(db.Model):
    __tablename__ = "screens"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    theatre_id = db.Column(
        db.Integer, db.ForeignKey("theatres.id"), nullable=False
    )


# SHOW MODEL: Define movie show timings, screens, and ticket prices
class Show(db.Model):
    __tablename__ = "shows"

    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(
        db.Integer, db.ForeignKey("movies.id"), nullable=False
    )
    screen_id = db.Column(
        db.Integer, db.ForeignKey("screens.id"), nullable=False
    )
    start_time = db.Column(db.DateTime, nullable=False)
    price = db.Column(db.Numeric(8, 2), nullable=False)


# HEALTH CHECK API: Check whether the Flask application is running
@app.route("/")
def hello():
    return jsonify({"status": "ok"})



# POST API - USER REGISTRATION: Receive user details and create an account
@app.route("/users", methods=["POST"])
def create_user():

    # Read JSON data from the request
    data = request.get_json()

    # Validate that JSON data was provided
    if not data:
        return jsonify({"error": "JSON data is required"}), 400

    # Extract registration details from the JSON data
    name = data.get("name")
    dob = data.get("dob")
    gender = data.get("gender")
    email = data.get("email")
    password = data.get("password")

    # Validate required fields
    if not name:
        return jsonify({"error": "Name is required"}), 400

    if not dob:
        return jsonify({"error": "Date of Birth is required"}), 400

    # Convert the date string into a Python date object
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

    # Check whether the email already exists in the database
    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({"error": "Email already exists"}), 409

    # Hash the password before saving it
    hashed_password = generate_password_hash(password)

    # Create a new user record
    new_user = User(
        name=name,
        dob=dob,
        gender=gender,
        email=email,
        password_hash=hashed_password
    )

    # Save the new user to MySQL
    db.session.add(new_user)
    db.session.commit()

    # Return the registration success response
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



# POST API - USER LOGIN: Verify credentials and generate a JWT token
@app.route("/login", methods=["POST"])
def login():

    # Read JSON data; use an empty dictionary if parsing fails
    request_data = request.get_json(silent=True) or {}

    # Extract login credentials
    email = request_data.get("email")
    password = request_data.get("password")

    # Validate that email and password are provided
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Find the user by email
    found_user = User.query.filter_by(email=email).first()

    # Verify the user exists and the password matches its hash
    if found_user is None or not check_password_hash(
        found_user.password_hash, password
    ):
        return jsonify({"error": "Invalid email or password"}), 401

    # Create JWT payload containing user ID and token expiry time
    payload = {
        "sub": str(found_user.id),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
    }

    # Generate a signed JWT token
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    # Return the token after successful login
    return jsonify({"token": token, "name": found_user.name}), 200



# AUTHENTICATION DECORATOR: Protect routes by checking the JWT token
def login_required(f):

    # Wrapper runs before the protected route
    @wraps(f)
    def wrapper(*args, **kwargs):

        # Read the Authorization header
        auth_header = request.headers.get("Authorization", "")

        # Check that the header uses the Bearer token format
        if not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "token is missing or malformed"
            }), 401

        # Extract the token from the header
        token = auth_header.split(" ")[1]

        # Verify the token and check its expiry
        try:
            payload = jwt.decode(
                token, SECRET_KEY, algorithms=["HS256"]
            )

        # Return an error if the token has expired
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token has expired"}), 401

        # Return an error if the token is invalid
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        # Find the user associated with the token
        found_user = User.query.filter_by(
            id=int(payload["sub"])
        ).first()

        # Reject the request if the user no longer exists
        if found_user is None:
            return jsonify({"error": "user not found"}), 401

        # Store the authenticated user for this request
        g.user = found_user

        # Continue to the protected route
        return f(*args, **kwargs)

    return wrapper


# GET API - USER PROFILE: Return profile details for the logged-in user
@app.route("/me", methods=["GET"])
@login_required
def me():

    # Return the authenticated user's profile as JSON
    return jsonify({
        "id": g.user.id,
        "name": g.user.name,
        "email": g.user.email,
        "dob": g.user.dob.isoformat(),
        "gender": g.user.gender,
    }), 200


# APPLICATION ENTRY POINT: Create tables and start the Flask server
if __name__ == "__main__":

    # Create database tables if they do not already exist
    with app.app_context():
        db.create_all()

    # Start the Flask development server
    app.run(debug=True)
