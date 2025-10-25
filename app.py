import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Custom filter
# app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")

# Ensure environment variable is set for API key if needed later
# if not os.environ.get("API_KEY"):
#     raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()
    
    # Handle POST request
    if request.method == "POST":
        
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)
        
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        
        # Convert username to lowercase to match to database storage
        username = request.form.get("username").lower()
                
        # Query database for username
        user = db.execute("SELECT * FROM users WHERE username = ?", username)
        
        # Ensure username exists and password is correct
        if len(user) != 1 or not check_password_hash(
            user[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)
        
        # Log user in by storing their id in session
        session["user_id"] = user[0]["id"]
        return redirect("/")
    
    # Handle GET request
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Handle POST request
    if request.method == "POST":
        
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Must provide username", 400)
        
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Must provide password", 400)
        
        # Ensure password is at least 8 characters
        password = request.form.get("password")
        if len(password) < 8:
            return apology("Password must be at least 8 characters", 400)
        
        #ensure confirmation was submitted
        confirmation = request.form.get("confirmation")
        if not confirmation or password != confirmation:
            return apology("Passwords do not match", 400)
        
        # Hash password 
        hash = generate_password_hash(request.form.get("password"))
        username = request.form.get("username").lower()
        
        # Try to insert new user into users table
        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)",
                username,
                hash,
            )
        except Exception:
            return apology("Username already exists", 400)
        
        # Query database for username
        rows = db.execute("SELECT id FROM users WHERE username = ?", username)
        
        # Log user in by storing their id in session
        session["user_id"] = rows[0]["id"]

        flash("Successfully registered!")
        return redirect("/")
    
    # Handle GET request
    else:
        return render_template("register.html")
    
@app.route("/pin", methods=["POST"])
@login_required
def pin():
    """Handles the form submission from the map.html to save a new stamp."""

    # 1. Retrieve data from the submitted form
    latitude_str = request.form.get("latitude")
    longitude_str = request.form.get("longitude")
    location_name = request.form.get("location_name")
    source = request.form.get("source")
    user_id = session["user_id"]

    # 2. Validation Checks
    if not location_name or not source:
        return apology("Must provide a location name and source of fiction", 400)

    try:
        # Convert string coordinates to floats for database storage and validation
        latitude = float(latitude_str)
        longitude = float(longitude_str)
    except (ValueError, TypeError):
        return apology("Invalid coordinates received. Please click on the map.", 400)

    # Simple check to ensure coordinates are within valid range (optional but good)
    if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
        return apology("Invalid geographic coordinates.", 400)


    # 3. Insert the new stamp into the 'stamps' table
    try:
        db.execute(
            "INSERT INTO stamps (user_id, location_name, source, latitude, longitude) VALUES (?, ?, ?, ?, ?)",
            user_id,
            location_name,
            source,
            latitude,
            longitude
        )
        flash(f"Passport stamped for {location_name} (from {source})!")
        return redirect("/")

    except Exception:
        # Catch unexpected database errors
        return apology("An unexpected database error occurred while stamping your passport.", 500)
    

@app.route("/map")
@login_required
def map_page():
    """Shows the user's interactive map with all stamped locations."""
    
    # 1. Get the current user's ID
    user_id = session["user_id"]
    
    # 2. Query all stamps for the current user
    # Ensure your database has the 'stamps' table created!
    stamps = db.execute(
        "SELECT location_name, source, latitude, longitude FROM stamps WHERE user_id = ?",
        user_id
    )
    
    # 3. Render the map and pass the stamp data to the template
    return render_template("map.html", stamps=stamps)


       
