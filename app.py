import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    # get user´s owned stocks
    owned = db.execute(
        "SELECT symbol, SUM(shares) AS total FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", session[
            "user_id"]
    )

    # get the current price, make sure variables are floats
    for stock in owned:
        quote = lookup(stock["symbol"])
        stock["price"] = float(quote["price"])
        stock["total"] = float(stock["total"])

    # get user´s cash, make sure variable is float
    user = db.execute(
        "SELECT cash FROM users WHERE id = ?", session["user_id"]
    )
    cash = float(user[0]["cash"])
    return render_template("index.html", owned=owned, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        # Ensure symbol was submitted
        shares_str = request.form.get("shares")
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        # Ensure shares was submitted
        elif not shares_str or not shares_str.isdigit() or int(shares_str) <= 0:
            return apology("shares must be a positive integer", 400)

        # ensure the user has enough money
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", session["user_id"]
        )
        if len(user) != 1:
            return apology("user not found", 400)

        symbol = request.form.get("symbol")
        stock = lookup(symbol)
        if not stock:
            return apology("invalid symbol", 400)

        shares = int(request.form.get("shares"))
        if stock["price"] * shares > user[0]["cash"]:
            return apology("you do not have enough cash", 400)

        # actualice the user´s cash
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", user[0]["cash"] -
            stock["price"] * shares, session["user_id"]
        )

        # Save the information about the purchase
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session[
                "user_id"], stock["symbol"], shares, stock["price"]
        )

        # flash a message
        flash("purchase complete!")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # get user´s history transactions ordered from the oldest to the newest
    history = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY transacted", session["user_id"]
    )

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    elif request.method == "POST":
        if not request.form.get("symbol"):
            # Ensure symbol was submitted
            return apology("must provide symbol", 400)
        symbol = request.form.get("symbol")
        # Pass symbol as an input of lookup and get stock
        stock = lookup(symbol)
        if not stock:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", symbol=symbol, stock=stock)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Check password and confirmation are equal
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation don´t match", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username doesn´t exist in my data base
        if len(rows) == 1:
            return apology("this username is taken", 400)

        # Add new user to my database
        else:
            username = request.form.get("username")
            hashed_password = generate_password_hash(request.form.get("password"))
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                       username, hashed_password)

        # Remember which user has logged in
        row = db.execute(
            "SELECT * FROM users WHERE username = (?)", request.form.get("username")
        )

        # The query returns no rows
        if len(row) != 1:
            return apology("user not found", 400)

        session["user_id"] = row[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    if request.method == "GET":
        stocks = db.execute(
            "SELECT symbol, SUM(shares) as total FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total > 0", session[
                "user_id"]
        )
        return render_template("sell.html", stocks=stocks)

    if request.method == "POST":
        # Ensure symbol was submitted

        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        # Ensure shares was submitted
        try:
            shares = int(request.form.get("shares"))
        except (TypeError, ValueError):
            return apology("shares must be a positive integer", 400)

        if shares <= 0:
            return apology("shares must be a positive integer", 400)

        # Ensure the user has enough shares of that company
        symbol = request.form.get("symbol")

        owned_shares = db.execute(
            "SELECT SUM(shares) AS total FROM transactions WHERE user_id = ? AND symbol = ?", session[
                "user_id"], symbol
        )

        if not owned_shares or owned_shares[0]["total"] is None or owned_shares[0]["total"] <= 0:
            return apology("you do not own any shares of this company", 400)

        if shares > owned_shares[0]["total"]:
            return apology("you do not have enough shares", 400)

        # update user´s cash
        stock = lookup(symbol)
        if not stock:
            return apology("invalid symbol", 400)

        user = db.execute(
            "SELECT * FROM users WHERE id = ?", session["user_id"]
        )
        cash = user[0]["cash"]
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", cash +
            stock["price"] * shares, session["user_id"]
        )

        # Save the information about the purchase
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session[
                "user_id"], stock["symbol"], -shares, stock["price"]
        )

        # flash a message
        flash("sale made!")
        return redirect("/")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():

    if request.method == "GET":
        return render_template("account.html")

    if request.method == "POST":
        # check the correct value of cash
        try:
            added_cash = float(request.form.get("cash"))
        except (TypeError, ValueError):
            return apology("must provide a valid number", 400)

        if added_cash < 1 or added_cash > 500:
            return apology("must provide a number between 1 and 500", 400)

        # check passworg
        if not request.form.get("password"):
            return apology("must provide password")

        # get user info
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", session["user_id"]
        )
        if len(user) != 1 or not check_password_hash(
            user[0]["hash"], request.form.get("password")
        ):
            return apology("invalid user and/or password", 400)

        # update user´s cash
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", user[0]["cash"] +
            added_cash, session["user_id"]
        )

        flash("cash added successfully!")
        return redirect("/")