
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from dotenv import load_dotenv
from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.exc import IntegrityError

load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY")

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mysql+pymysql://root:@localhost:3306/ticket_booking"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# USER MODEL
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


# MOVIE MODEL
class Movie(db.Model):
    __tablename__ = "movies"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    genre = db.Column(db.String(50))


# THEATRE MODEL
class Theatre(db.Model):
    __tablename__ = "theatres"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)



# SCREEN MODEL
class Screen(db.Model):
    __tablename__ = "screens"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    theatre_id = db.Column(
        db.Integer,
        db.ForeignKey("theatres.id"),
        nullable=False
    )



# SHOW MODEL
class Show(db.Model):
    __tablename__ = "shows"

    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(
        db.Integer,
        db.ForeignKey("movies.id"),
        nullable=False
    )
    screen_id = db.Column(
        db.Integer,
        db.ForeignKey("screens.id"),
        nullable=False
    )
    start_time = db.Column(db.DateTime, nullable=False)
    price = db.Column(db.Numeric(8, 2), nullable=False)


# BOOKING MODEL
class Booking(db.Model):
    __tablename__ = "bookings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False
    )
    show_id = db.Column(
        db.Integer, db.ForeignKey("shows.id"), nullable=False
    )
    seat_number = db.Column(db.String(10), nullable=False)
    booked_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint(
            "show_id", "seat_number",
            name="unique_show_seat"
        ),
    )



# AUTHENTICATION DECORATOR
# Define this BEFORE any route using @login_required
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "token is missing or malformed"
            }), 401

        token = auth_header.split(" ", 1)[1]

        try:
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=["HS256"]
            )

            user_id = int(payload["sub"])

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token has expired"}), 401

        except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
            return jsonify({"error": "invalid token"}), 401

        found_user = db.session.get(User, user_id)

        if found_user is None:
            return jsonify({"error": "user not found"}), 401

        g.user = found_user

        return f(*args, **kwargs)

    return wrapper



# HEALTH CHECK API
@app.route("/")
def hello():
    return jsonify({"status": "ok"}), 200




# USER REGISTRATION API
@app.route("/users", methods=["POST"])
def create_user():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "JSON data is required"}), 400

    name = data.get("name")
    dob = data.get("dob")
    gender = data.get("gender")
    email = data.get("email")
    password = data.get("password")

    if not isinstance(name, str) or not name.strip():
        return jsonify({"error": "Name is required"}), 400

    if not dob:
        return jsonify({"error": "Date of Birth is required"}), 400

    try:
        dob = datetime.strptime(dob, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return jsonify({
            "error": "dob must be in YYYY-MM-DD format"
        }), 400

    if not isinstance(gender, str) or not gender.strip():
        return jsonify({"error": "Gender is required"}), 400

    if not isinstance(email, str) or not email.strip():
        return jsonify({"error": "Email is required"}), 400

    if not isinstance(password, str) or not password:
        return jsonify({"error": "Password is required"}), 400

    email = email.strip().lower()

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({"error": "Email already exists"}), 409

    new_user = User(
        name=name.strip(),
        dob=dob,
        gender=gender.strip(),
        email=email,
        password_hash=generate_password_hash(password)
    )

    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

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



# USER LOGIN API
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Email and password are required"
        }), 400

    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not email.strip():
        return jsonify({
            "error": "Email and password are required"
        }), 400

    if not isinstance(password, str) or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    if not SECRET_KEY:
        return jsonify({
            "error": "Server secret key is not configured"
        }), 500

    found_user = User.query.filter_by(
        email=email.strip().lower()
    ).first()

    if found_user is None or not check_password_hash(
        found_user.password_hash, password
    ):
        return jsonify({"error": "Invalid email or password"}), 401

    payload = {
        "sub": str(found_user.id),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "token": token,
        "name": found_user.name
    }), 200



# ADMIN CHECK DECORATOR
# Always use it BELOW @login_required
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not g.user.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return wrapper



# GET ALL MOVIES
@app.route("/movies", methods=["GET"])
def get_movies():
    movies = Movie.query.all()

    return jsonify({
        "movies": [
            {
                "id": movie.id,
                "title": movie.title,
                "duration_minutes": movie.duration_minutes,
                "language": movie.language,
                "genre": movie.genre
            }
            for movie in movies
        ]
    }), 200



# GET MOVIE BY ID
@app.route("/movies/<int:movie_id>", methods=["GET"])
def get_movie(movie_id):
    movie = db.session.get(Movie, movie_id)

    if movie is None:
        return jsonify({"error": "Movie not found"}), 404

    return jsonify({
        "id": movie.id,
        "title": movie.title,
        "duration_minutes": movie.duration_minutes,
        "language": movie.language,
        "genre": movie.genre
    }), 200



# ADD MOVIE - ADMIN ONLY
@app.route("/movies", methods=["POST"])
@login_required
def add_movie():
    if not g.user.is_admin:
        return jsonify({"error": "Admin access required"}), 403

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Valid JSON data is required"}), 400

    title = data.get("title")
    duration = data.get("duration_minutes")
    language = data.get("language")
    genre = data.get("genre")

    if not isinstance(title, str) or not title.strip():
        return jsonify({"error": "Title is required"}), 400

    if not isinstance(language, str) or not language.strip():
        return jsonify({"error": "Language is required"}), 400

    if (
        isinstance(duration, bool)
        or not isinstance(duration, int)
        or duration <= 0
    ):
        return jsonify({
            "error": "Duration must be a positive integer"
        }), 400

    if genre is not None and not isinstance(genre, str):
        return jsonify({"error": "Genre must be text or null"}), 400

    movie = Movie(
        title=title.strip(),
        duration_minutes=duration,
        language=language.strip(),
        genre=genre.strip() if genre and genre.strip() else None
    )

    db.session.add(movie)
    db.session.commit()

    return jsonify({
        "message": "Movie added successfully",
        "movie": {
            "id": movie.id,
            "title": movie.title,
            "duration_minutes": movie.duration_minutes,
            "language": movie.language,
            "genre": movie.genre
        }
    }), 201



# UPDATE MOVIE - ADMIN ONLY
@app.route("/movies/<int:movie_id>", methods=["PUT"])
@login_required
def update_movie(movie_id):
    if not g.user.is_admin:
        return jsonify({"error": "Admin access required"}), 403

    movie = db.session.get(Movie, movie_id)

    if movie is None:
        return jsonify({"error": "Movie not found"}), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data:
        return jsonify({
            "error": "Valid JSON data is required"
        }), 400

    if "title" in data:
        title = data["title"]

        if not isinstance(title, str) or not title.strip():
            return jsonify({"error": "Title cannot be empty"}), 400

        movie.title = title.strip()

    if "duration_minutes" in data:
        duration = data["duration_minutes"]

        if (
            isinstance(duration, bool)
            or not isinstance(duration, int)
            or duration <= 0
        ):
            return jsonify({
                "error": "Duration must be a positive integer"
            }), 400

        movie.duration_minutes = duration

    if "language" in data:
        language = data["language"]

        if not isinstance(language, str) or not language.strip():
            return jsonify({
                "error": "Language cannot be empty"
            }), 400

        movie.language = language.strip()

    if "genre" in data:
        genre = data["genre"]

        if genre is not None and not isinstance(genre, str):
            return jsonify({
                "error": "Genre must be text or null"
            }), 400

        movie.genre = genre.strip() if genre and genre.strip() else None

    db.session.commit()

    return jsonify({
        "message": "Movie updated successfully",
        "movie": {
            "id": movie.id,
            "title": movie.title,
            "duration_minutes": movie.duration_minutes,
            "language": movie.language,
            "genre": movie.genre
        }
    }), 200



# DELETE MOVIE - ADMIN ONLY
@app.route("/movies/<int:movie_id>", methods=["DELETE"])
@login_required
def delete_movie(movie_id):
    if not g.user.is_admin:
        return jsonify({"error": "Admin access required"}), 403

    movie = db.session.get(Movie, movie_id)

    if movie is None:
        return jsonify({"error": "Movie not found"}), 404

    db.session.delete(movie)
    db.session.commit()

    return jsonify({"message": "Movie deleted successfully"}), 200



# ADD THEATRE - ADMIN ONLY
@app.route("/theatres", methods=["POST"])
@login_required
@admin_required
def add_theatre():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Valid JSON data is required"}), 400

    name = data.get("name")
    city = data.get("city")

    if not isinstance(name, str) or not name.strip():
        return jsonify({"error": "Name is required"}), 400

    if not isinstance(city, str) or not city.strip():
        return jsonify({"error": "City is required"}), 400

    theatre = Theatre(name=name.strip(), city=city.strip())

    db.session.add(theatre)
    db.session.commit()

    return jsonify({
        "message": "Theatre added successfully",
        "theatre": {
            "id": theatre.id,
            "name": theatre.name,
            "city": theatre.city
        }
    }), 201



# GET ALL THEATRES (optional ?city= filter)
@app.route("/theatres", methods=["GET"])
def get_theatres():
    city = request.args.get("city")

    query = Theatre.query

    if city:
        query = query.filter_by(city=city.strip())

    theatres = query.all()

    return jsonify({
        "theatres": [
            {
                "id": theatre.id,
                "name": theatre.name,
                "city": theatre.city
            }
            for theatre in theatres
        ]
    }), 200



# ADD SCREEN - ADMIN ONLY
@app.route("/screens", methods=["POST"])
@login_required
@admin_required
def add_screen():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Valid JSON data is required"}), 400

    name = data.get("name")
    theatre_id = data.get("theatre_id")

    if not isinstance(name, str) or not name.strip():
        return jsonify({"error": "Name is required"}), 400

    if (
        isinstance(theatre_id, bool)
        or not isinstance(theatre_id, int)
        or theatre_id <= 0
    ):
        return jsonify({"error": "theatre_id must be a positive integer"}), 400

    # <-- your theatre check goes here
    theatre = db.session.get(Theatre, theatre_id)
    if theatre is None:
        return jsonify({"error": "Theatre not found"}), 404

    screen = Screen(name=name.strip(), theatre_id=theatre_id)

    db.session.add(screen)
    db.session.commit()

    return jsonify({
        "message": "Screen added successfully",
        "screen": {
            "id": screen.id,
            "name": screen.name,
            "theatre_id": screen.theatre_id
        }
    }), 201



# GET ALL SCREENS (optional ?theatre_id= filter)
@app.route("/screens", methods=["GET"])
def get_screens():
    theatre_id = request.args.get("theatre_id", type=int)

    if "theatre_id" in request.args and theatre_id is None:
        return jsonify({"error": "theatre_id must be an integer"}), 400

    query = Screen.query

    if theatre_id is not None:
        query = query.filter_by(theatre_id=theatre_id)

    screens = query.all()

    return jsonify({
        "screens": [
            {
                "id": screen.id,
                "name": screen.name,
                "theatre_id": screen.theatre_id
            }
            for screen in screens
        ]
    }), 200




# POST API - ADD SHOW (ADMIN ONLY)
@app.route("/shows", methods=["POST"])
@login_required
@admin_required
def add_show():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Valid JSON data is required"}), 400

    movie_id = data.get("movie_id")
    screen_id = data.get("screen_id")
    start_time = data.get("start_time")
    price = data.get("price")

    if not movie_id or not screen_id or not start_time or price is None:
        return jsonify({"error": "All fields are required"}), 400

    try:
        start_time = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S")
        price = float(price)

        if price <= 0:
            return jsonify({"error": "Price must be positive"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid start_time or price"}), 400

    movie = db.session.get(Movie, movie_id)
    screen = db.session.get(Screen, screen_id)

    if movie is None:
        return jsonify({"error": "Movie not found"}), 404

    if screen is None:
        return jsonify({"error": "Screen not found"}), 404

    show = Show(
        movie_id=movie_id,
        screen_id=screen_id,
        start_time=start_time,
        price=price
    )

    db.session.add(show)
    db.session.commit()

    return jsonify({
        "message": "Show scheduled successfully",
        "show": {
            "id": show.id,
            "movie_id": show.movie_id,
            "screen_id": show.screen_id,
            "start_time": show.start_time.isoformat(),
            "price": str(show.price)
        }
    }), 201


# GET API - GET ALL SHOWS
@app.route("/shows", methods=["GET"])
def get_shows():
    results = db.session.query(Show, Movie, Screen, Theatre).join(
        Movie, Show.movie_id == Movie.id
    ).join(
        Screen, Show.screen_id == Screen.id
    ).join(
        Theatre, Screen.theatre_id == Theatre.id
    ).order_by(Show.start_time).all()

    return jsonify({
        "shows": [
            {
                "id": show.id,
                "movie_id": movie.id,
                "movie_title": movie.title,
                "screen_id": screen.id,
                "screen_name": screen.name,
                "theatre_id": theatre.id,
                "theatre_name": theatre.name,
                "city": theatre.city,
                "start_time": show.start_time.isoformat(),
                "price": str(show.price)
            }
            for show, movie, screen, theatre in results
        ]
    }), 200


# GET API - GET SHOWS FOR A PARTICULAR MOVIE
@app.route("/movies/<int:movie_id>/shows", methods=["GET"])
def get_movie_shows(movie_id):
    movie = db.session.get(Movie, movie_id)

    if movie is None:
        return jsonify({"error": "Movie not found"}), 404

    results = db.session.query(Show, Screen, Theatre).join(
        Screen, Show.screen_id == Screen.id
    ).join(
        Theatre, Screen.theatre_id == Theatre.id
    ).filter(
        Show.movie_id == movie_id
    ).order_by(Show.start_time).all()

    return jsonify({
        "movie": {
            "id": movie.id,
            "title": movie.title
        },
        "shows": [
            {
                "id": show.id,
                "screen_id": screen.id,
                "screen_name": screen.name,
                "theatre_id": theatre.id,
                "theatre_name": theatre.name,
                "city": theatre.city,
                "start_time": show.start_time.isoformat(),
                "price": str(show.price)
            }
            for show, screen, theatre in results
        ]
    }), 200



# POST API - BOOK A TICKET
@app.route("/bookings", methods=["POST"])
@login_required
def create_booking():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Valid JSON data is required"}), 400

    show_id = data.get("show_id")
    seat_number = data.get("seat_number")

    if isinstance(show_id, bool) or not isinstance(show_id, int) or show_id <= 0:
        return jsonify({"error": "Valid show_id is required"}), 400

    if not isinstance(seat_number, str) or not seat_number.strip():
        return jsonify({"error": "Seat number is required"}), 400

    seat_number = seat_number.strip().upper()

    if len(seat_number) > 10:
        return jsonify({"error": "Seat number is too long"}), 400

    show = db.session.get(Show, show_id)

    if show is None:
        return jsonify({"error": "Show not found"}), 404

    booking = Booking(
        user_id=g.user.id,
        show_id=show_id,
        seat_number=seat_number
    )

    db.session.add(booking)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Seat already booked for this show"}), 409

    return jsonify({
        "message": "Ticket booked successfully",
        "booking": {
            "id": booking.id,
            "show_id": booking.show_id,
            "seat_number": booking.seat_number
        }
    }), 201


# GET API - GET MY BOOKINGS
@app.route("/bookings/my", methods=["GET"])
@login_required
def get_my_bookings():
    bookings = Booking.query.filter_by(
        user_id=g.user.id
    ).order_by(Booking.booked_at.desc()).all()

    return jsonify({
        "bookings": [
            {
                "id": booking.id,
                "show_id": booking.show_id,
                "seat_number": booking.seat_number,
                "booked_at": booking.booked_at.isoformat()
            }
            for booking in bookings
        ]
    }), 200


# DELETE API - CANCEL MY BOOKING
@app.route("/bookings/<int:booking_id>", methods=["DELETE"])
@login_required
def cancel_booking(booking_id):
    booking = Booking.query.filter_by(
        id=booking_id,
        user_id=g.user.id
    ).first()

    if booking is None:
        return jsonify({"error": "Booking not found"}), 404

    db.session.delete(booking)
    db.session.commit()

    return jsonify({
        "message": "Booking cancelled successfully"
    }), 200




# GET LOGGED-IN USER PROFILE
@app.route("/me", methods=["GET"])
@login_required
def me():
    return jsonify({
        "id": g.user.id,
        "name": g.user.name,
        "email": g.user.email,
        "dob": g.user.dob.isoformat(),
        "gender": g.user.gender
    }), 200


# APPLICATION ENTRY POINT
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
