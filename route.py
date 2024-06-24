import logging
from flask import Flask, request, jsonify
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import urllib.parse as urlparse
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timedelta
import uuid
import jwt
from flask_cors import CORS
from functools import wraps


SECRET_KEY = "1234"
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'pradeep123'
login_manager = LoginManager()
login_manager.init_app(app)

database_url = os.getenv('DATABASE_URL', 'postgresql://postgres:pradeeppinaca@localhost:5432/demo')
url = urlparse.urlparse(database_url)
dbname = url.path[1:]
user = url.username
password = url.password
host = url.hostname
port = url.port

def get_db_connection():
    conn = psycopg2.connect(
        dbname=dbname,
        user=user,
        password=password,
        host=host,
        port=port
    )
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            full_name VARCHAR(100),
            email VARCHAR(100) UNIQUE,
            phone VARCHAR(20),
            password VARCHAR(200),
            dob DATE,
            address TEXT,
            country VARCHAR(100),
            gender VARCHAR(10)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS flight_table (
            flight_id VARCHAR(100) PRIMARY KEY,
            airline VARCHAR(100),
            flight_number VARCHAR(10),
            departure_city VARCHAR(100),
            arrival_city VARCHAR(100),
            departure_time TIMESTAMP,
            arrival_time TIMESTAMP,
            price DECIMAL(10, 2)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS cab (
            id SERIAL PRIMARY KEY,
            rental_company VARCHAR(100),
            city VARCHAR(100),
            pick_up_location VARCHAR(100),
            where_to_go VARCHAR(100),
            car_model VARCHAR(100),
            available_cars INTEGER,
            rental_price DECIMAL(10, 2)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS flight_booking (
            id SERIAL PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            user_id VARCHAR(50) NOT NULL ,
            departure_city VARCHAR(100) NOT NULL,
            arrival_city VARCHAR(100) NOT NULL,
            seat_number VARCHAR(10) NOT NULL,
            flight_time TIMESTAMP NOT NULL,
            airline VARCHAR(100) NOT NULL,
            flight_id VARCHAR(50) NOT NULL,
            booking_date DATE NOT NULL,
            num_adults INTEGER NOT NULL,
            num_children INTEGER NOT NULL,
            total_travelers INTEGER NOT NULL
        )
    ''')


    cur.execute('''
        CREATE TABLE IF NOT EXISTS hotel_booking (
            id SERIAL PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            hotel_name VARCHAR(100) NOT NULL,
            city VARCHAR(50) NOT NULL,
            address VARCHAR(100) NOT NULL,
            num_rooms INTEGER NOT NULL,
            num_guests INTEGER NOT NULL,
            booking_date TIMESTAMP DEFAULT NOW(),
            checkin_time TIMESTAMP,
            checkout_time TIMESTAMP,
            price DECIMAL(10, 2)
        )
    ''')

    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS role_table (
            Role_id SERIAL PRIMARY KEY,
            role_name VARCHAR(100) NOT NULL,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )

    ''')

    cur.execute('''

        CREATE TABLE IF NOT EXISTS cab_booking (
            id SERIAL PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL,
            rental_company VARCHAR(100) NOT NULL,
            city VARCHAR(100) NOT NULL,
            pick_up_location VARCHAR(100) NOT NULL,
            where_to_go VARCHAR(100) NOT NULL
        );

    ''')    

    conn.commit()
    cur.close()
    conn.close()

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def authorize_request(request):
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split()[1]
    else:
        return jsonify({"error": "Authorization header missing or malformed"}), 401

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    return None, payload

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    full_name = data.get("full_name")
    email = data.get("email")
    password = data.get("password")
    phone = data.get("phone")
    dob = data.get("dob")
    address = data.get("address")
    country = data.get("country")
    gender = data.get("gender")

    if not all([full_name, email, password, phone, dob, address, country, gender]):
        return jsonify({"message": "All fields are required"}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""SELECT "email" FROM "users" WHERE "email" = %s""", (email,))
    existing_user = cur.fetchone()

    if existing_user:
        cur.close()
        conn.close()
        return jsonify({"message": "Email already exists"}), 400

    hashed_password = pbkdf2_sha256.hash(password)
    cur.execute(
        """INSERT INTO "users" ("full_name", "email", "phone", "password", "dob", "address", "country", "gender") VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (full_name, email, phone, hashed_password, dob, address, country, gender)
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "User registered successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""SELECT "id","full_name", "country", "password" , "gender" , "dob" FROM "users" WHERE "email" = %s""", (email,))
    user = cur.fetchone()
    print(f"user : {user}")
    id, full_name, country, hashed_password, gender, dob = user
    
    print(f"hashed_password : {hashed_password}")
    print(f"hashed_password :",user["password"])


    if pbkdf2_sha256.verify(password, user["password"]):
        login_user(User(user['id']))
        payload = {
            "full_name": user["full_name"],
            "gender": user["gender"],
            "country": user["country"],
            "user_id": user["id"],
            "email": email,
            "exp": datetime.utcnow() + timedelta(days=1)

        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        cur.close()
        conn.close()
        return jsonify({"token": token}), 200
    else:
        cur.close()
        conn.close()
        return jsonify({"message": "Invalid email or password"}), 401


@app.route("/logout", methods=["POST"])
def logout():
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response
    logout_user()
    return jsonify({"message": "Logout successful"}), 200


# @app.route("/profile")
# @login_required
# def profile():
#     return jsonify({"message": "User profile"}), 200

class User(UserMixin):
    def __init__(self, id, full_name, email, phone, dob, address, country, gender):
        self.id = id
        self.full_name = full_name
        self.email = email
        self.phone = phone
        self.dob = dob
        self.address = address
        self.country = country
        self.gender = gender


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""SELECT * FROM users WHERE id = %s""", (user_id,))
    user_data = cur.fetchone()
    cur.close()
    conn.close()

    if user_data:
        return User(user_id=user_data['id'],
                    full_name=user_data['full_name'],
                    email=user_data['email'],
                    phone=user_data['phone'],
                    dob=user_data['dob'],
                    address=user_data['address'],
                    country=user_data['country'],
                    gender=user_data['gender'])
    return None


@app.route('/user_profile/<user_id>', methods=['GET'])
@login_required
def user_profile(user_id):
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response

    if current_user.id != 1:  
        return jsonify({"message": "Unauthorized access"}), 403

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""SELECT * FROM users WHERE id = %s""", (user_id,))
    user_profile = cur.fetchone()
    cur.close()
    conn.close()

    if not user_profile:
        return jsonify({"message": "User profile not found"}), 404

    return jsonify(user_profile), 200

@app.route('/admin_only_endpoint', methods=['GET'])
@login_required
def admin_only_endpoint():
    error_response, payload = authorize_request(request, 'admin')
    if error_response:
        return error_response
    return jsonify({"message": "Admin only endpoint accessed"})

@app.route('/user_accessible_endpoint', methods=['GET'])
@login_required
def user_accessible_endpoint():
    error_response, payload = authorize_request(request, 'traveler')
    if error_response:
        return error_response
    return jsonify({"message": "User accessible endpoint accessed"})


@app.route('/add-flight', methods=['POST'])
def add_flight():
    data = request.get_json()
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response
    if not isinstance(data, list):
        return jsonify({"message": "Invalid input, expected a list of JSON objects"}), 400
    
    for flight in data:
        flight_id = flight.get('flight_id')
        airline = flight.get('airline')
        flight_number = flight.get('flight_number')
        departure_city = flight.get('departure_city')
        arrival_city = flight.get('arrival_city')
        departure_time = flight.get('departure_time')
        arrival_time = flight.get('arrival_time')
        price = flight.get('price')

        if not all([flight_id, airline, flight_number, departure_city, arrival_city, departure_time, arrival_time, price]):
            return jsonify({"message": "All fields are required for each flight"}), 400

        try:
            departure_time = datetime.strptime(departure_time, '%Y-%m-%d %H:%M:%S')
            arrival_time = datetime.strptime(arrival_time, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return jsonify({"message": f"Invalid date format for flight {flight_number}, expected 'YYYY-MM-DD HH:MM:SS'"}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            '''INSERT INTO flight_table (flight_id, airline, flight_number, departure_city, arrival_city, departure_time, arrival_time, price)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
            (flight_id, airline, flight_number, departure_city, arrival_city, departure_time, arrival_time, price)
        )
        conn.commit()
        cur.close()
        conn.close()

    return jsonify({"message": "Flights added successfully"}), 201


@app.route('/search/flight_rentals', methods=['GET'])
def search_flight_rentals():
    # error_response, payload = authorize_request(request)
    # if error_response:
    #     return error_response
    departure_city = request.args.get('departure_city')
    arrival_city = request.args.get('arrival_city')

    if not all([departure_city, arrival_city]):
        return jsonify({"message": "Both departure_city and arrival_city are required"}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT * FROM flight_table
        WHERE departure_city = %s AND arrival_city = %s
    """, (departure_city, arrival_city))
    flights = cur.fetchall()
    cur.close()
    conn.close()

    return jsonify(flights), 200


@app.route('/add_hotels', methods=['POST'])
@login_required
def add_hotels():
    data = request.get_json()
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response

    if not isinstance(data, list):
        return jsonify({"message": "Invalid input, expected a list of JSON objects"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    for hotel in data:    
        hotel_name = hotel.get("hotel_name")
        city = hotel.get("city")
        address = hotel.get("address")
        available_rooms = hotel.get("available_rooms")
        booking_date = hotel.get("booking_date")
        checkin_time = hotel.get("checkin_time")
        checkout_time = hotel.get("checkout_time")
        price = hotel.get("price")

        if not all([hotel_name, city, address, available_rooms, booking_date, checkin_time, checkout_time, price]):
            cur.close()
            conn.close()
            return jsonify({"message": "All fields are required for each hotel entry"}), 400

        cur.execute(
            '''INSERT INTO hotel_table (hotel_name, city, address, available_rooms, booking_date, checkin_time, checkout_time, price)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
            (hotel_name, city, address, available_rooms, booking_date, checkin_time, checkout_time, price)
        )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Hotel details added successfully"}), 201

@app.route('/search/hotels', methods=['GET'])
def search_hotels():
    # error_response, payload = authorize_request(request)
    # if error_response:
    #     return error_response
    city = request.args.get('city')
    checkin_time = request.args.get('checkin_time')
    checkout_time = request.args.get('checkout_time')

    if not all([city, checkin_time, checkout_time]):
        return jsonify({"message": "Missing required parameters"}), 400

    try:
        checkin_time = datetime.strptime(checkin_time, '%Y-%m-%d').date()
        checkout_time = datetime.strptime(checkout_time, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"message": "Invalid date format. Use YYYY-MM-DD"}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT * FROM hotel_table
        WHERE city = %s AND checkin_time <= %s AND checkout_time >= %s
    """, (city, checkout_time, checkin_time))

    hotels = cur.fetchall()
    cur.close()
    conn.close()

    return jsonify(hotels), 200


@app.route('/add_car_rental', methods=['POST'])
def add_car_rental():
    data = request.get_json()
    # error_response, payload = authorize_request(request)
    # if error_response:
    #     return error_response

    rental_company = data.get("rental_company")
    city = data.get("city")
    pick_up_location = data.get("pick_up_location")
    where_to_go = data.get("where_to_go")
    car_model = data.get("car_model")
    available_cars = data.get("available_cars")
    rental_price = data.get("rental_price")

    if not all([rental_company, city, pick_up_location, where_to_go, car_model, available_cars, rental_price]):
        return jsonify({"message": "All fields are required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''INSERT INTO cab (rental_company, city, pick_up_location, where_to_go, car_model, available_cars, rental_price)
        VALUES (%s, %s, %s, %s, %s, %s, %s)''',
        (rental_company, city, pick_up_location, where_to_go, car_model, available_cars, rental_price)
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Car rental added successfully"}), 201

@app.route('/search/car_rentals', methods=['GET'])
def search_car_rentals():
    # error_response, payload = authorize_request(request)
    # if error_response:
    #     return error_response
    pick_up_location = request.args.get('pick_up_location')
    where_to_go = request.args.get('where_to_go')

    if not all([pick_up_location, where_to_go]):
        return jsonify({"message": "Both pick_up_location and where_to_go are required"}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT * FROM cab
        WHERE pick_up_location = %s AND where_to_go = %s
    """, (pick_up_location, where_to_go))
    
    car_rentals = cur.fetchall()
    cur.close()
    conn.close()

    return jsonify(car_rentals), 200


@app.route('/book_flight', methods=['POST'])
def book_flight():
    data = request.get_json()

    #----------------------------------
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response
    
    #-------------------------------------
    if not data:
        return jsonify({'message': 'Invalid data!'}), 400

    user_id = payload.get("user_id")

    flight_number = data.get('flight_number')
    full_name = data.get('full_name')
    email = data.get('email')
    departure_city = data.get('departure_city')
    arrival_city = data.get('arrival_city')

    if not all([full_name, email, flight_number, departure_city, arrival_city]):
        return jsonify({'error': 'Invalid input'}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT * FROM flight_table
        WHERE flight_number = %s AND departure_city = %s AND arrival_city = %s
    """, (flight_number, departure_city, arrival_city))

    flight = cur.fetchone()
    print("flight",flight)
    if not flight:
        cur.close()
        conn.close()
        return jsonify({'error': 'Flight not available'}), 400

    booking_id = str(uuid.uuid4())

    try:
        cur.execute(
            '''INSERT INTO flight_booking (full_name, user_id, departure_city, arrival_city, seat_number, flight_time, airline, flight_id, booking_date, num_adults, num_children, total_travelers)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
            (full_name, user_id, departure_city, arrival_city, 'A1', flight["departure_time"], flight["airline"], flight["flight_id"], datetime.now().date(), 1, 0, 1)
        )

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'Booking successful', 'booking_id': booking_id}), 201
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        return jsonify({"message": "Error booking flight", "error": str(e)}), 500

        # ---------------------

@app.route('/book_hotel', methods=['POST'])
def book_hotel():
    data = request.get_json()
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response

    full_name = data.get('full_name')
    email = data.get('email')
    hotel_name = data.get('hotel_name')
    city = data.get('city')
    address = data.get('address')
    num_rooms = data.get('num_rooms')
    num_guests = data.get('num_guests')
    checkin_time = data.get('checkin_time')
    checkout_time = data.get('checkout_time')
    price = data.get('price')

    if not all([full_name, email, hotel_name, city, address, num_rooms, num_guests, checkin_time, checkout_time, price]):
        return jsonify({"message": "All fields are required"}), 400

    try:
        checkin_time = datetime.strptime(checkin_time, '%Y-%m-%d %H:%M:%S')
        checkout_time = datetime.strptime(checkout_time, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return jsonify({"message": "Invalid date format for checkin/checkout time, expected 'YYYY-MM-DD HH:MM:SS'"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        '''INSERT INTO hotel_booking (full_name, email, hotel_name, city, address, num_rooms, num_guests, checkin_time, checkout_time, price)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
        (full_name, email, hotel_name, city, address, num_rooms, num_guests, checkin_time, checkout_time, price)
    )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Hotel booked successfully"}), 201
    # except Exception as e:
    #     conn.rollback()
    #     cur.close()
    #     conn.close()
    #     return jsonify({"message": "Error booking hotel", "error": str(e)}), 500


@app.route('/book_cab', methods=['POST'])
def book_cab():
    data = request.get_json()
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response

    user_name = payload.get('full_name')
    email = payload.get('email')
    city = data.get('city')
    rental_company = data.get('rental_company')
    pick_up_location = data.get('pick_up_location')
    where_to_go = data.get('where_to_go')

    if not all([rental_company, city, pick_up_location, where_to_go]):
        return jsonify({'message': 'All fields are required'}), 400
    # try:
    #     pick_up_location = datetime.strptime(pick_up_location)
    #     where_to_go = datetime.strptime(where_to_go)    
    
    # except ValueError:
    #     return jsonify({"message": "Invalid date format for checkin/checkout time, expected 'YYYY-MM-DD HH:MM:SS'"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        '''INSERT INTO cab_booking (full_name, email, rental_company, city, pick_up_location, where_to_go)
        VALUES (%s,%s , %s, %s, %s, %s)''',
        (user_name, email,rental_company,city, pick_up_location, where_to_go)
    )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "cab booked successfully"}), 201

@app.route('/add-review', methods=['POST'])
@login_required
def add_review():
    data = request.get_json()
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response

    user_id = payload.get('user_id')
    service_type = data.get('service_type')
    service_id = data.get('service_id')
    rating = data.get('rating')
    review_text = data.get('review')

    if not all([service_type, service_id, rating, review_text]):
        return jsonify({"message": "All fields are required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        '''INSERT INTO reviews (user_id, service_type, service_id, rating, review)
        VALUES (%s, %s, %s, %s, %s)''',
        (user_id, service_type, service_id, rating, review_text)
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Review added successfully"}), 201    

@app.route('/get-reviews', methods=['GET'])
@login_required
def get_reviews():
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM reviews")
    reviews = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(reviews), 200        



@app.route('/admin/get-bookings', methods=['GET'])
@login_required
def get_bookings():
    error_response, payload = authorize_request(request)
    if error_response:
        return error_response

    if current_user.id != 1:
        return jsonify({"message": "Unauthorized access"}), 403

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM flight_booking UNION SELECT * FROM hotel_booking")
    bookings = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(bookings), 200

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)