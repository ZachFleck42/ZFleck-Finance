import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():

    # Obtain user information
    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    user_cash = user[0]["cash"]

    # Obtain user's holdings information
    holdings = db.execute("SELECT * FROM holdings WHERE user_id = ? ORDER BY symbol", user_id)

    # Obtain stock information
    stockList = []
    user_total = user_cash
    for holding in holdings:
        results = lookup(holding["symbol"])
        stockTotal = int(holding["shares"]) * float(results["price"])
        user_total += stockTotal
        tempDict = {"symbol": results["symbol"], "name": results["name"], "shares": holding["shares"], "price": results["price"], "total": stockTotal}
        stockList.append(tempDict)

    return render_template("index.html", stocks = stockList, user_cash = user_cash, user_total = user_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Obtain user information
        user_id = session["user_id"]
        user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        user_cash = user[0]["cash"]

        # Obtain stock information
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must enter a symbol")
        if not lookup(symbol):
            return apology("Must enter a valid symbol")
        results = lookup(symbol)
        name = results["name"]
        price = results["price"]

        # Error checking
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("must purchase a whole number of shares")
        if shares < 1:
            return apology("must purchase more than 0 shares")
        if (shares * price) > user_cash:
            return apology("cannot afford")


        # Add transaction to 'transactions' table
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, timestamp) VALUES (?, ?, ?, ?, ?, ?)", user_id, symbol, name, shares, price, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Update user's cash in 'users' table
        new_cash = user_cash - (shares * price)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        # Update user's holdings in 'holdings' table
        holdings = db.execute("SELECT * FROM holdings WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if len(holdings) != 1:
            db.execute("INSERT INTO holdings (user_id, symbol, name, shares) VALUES (?, ?, ?, ?)", user_id, symbol, name, shares)
        else:
            user_shares = holdings[0]["shares"]
            new_shares = user_shares + shares
            db.execute("UPDATE holdings SET shares = ? WHERE user_id = ? AND symbol = ?", new_shares, user_id, symbol)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Obtain user information
    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)

    # Obtain user's transaction history
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", user_id)

    return render_template("history.html", transactions = transactions)



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
        user = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(user) != 1 or not check_password_hash(user[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = user[0]["id"]

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
    """Get stock quote"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Obtain relevant data from IEX database
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must enter a symbol")
        if not lookup(symbol):
            return apology("Must enter a valid symbol")
        results = lookup(symbol)

        # Render new template with formatted results
        return render_template("quoted.html", name = results["name"], symbol = results["symbol"], price = results["price"])

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a new user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        username = request.form.get("username")
        if not username:
            return apology("must provide username")

        # Ensure username is unique (not already taken)
        user = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(user) > 0:
            return apology("username already taken")

        # Ensure password was submitted
        password1 = request.form.get("password")
        if not password1:
            return apology("must provide password")

        # Ensure password verification was submitted
        password2 = request.form.get("confirmation")
        if not password2:
            return apology("must verify password")

        # Ensure passwords match
        if password1 != password2:
            return apology("passwords did not match")

        # If no errors, hash password and insert new user into users table of database
        passwordHash = generate_password_hash(password1)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, passwordHash)

        # Log the user in
        user2 = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = user2[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    # Obtain user information
    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    user_cash = user[0]["cash"]

    # Obtain user's holdings information
    holdings = db.execute("SELECT * FROM holdings WHERE user_id = ? ORDER BY symbol", user_id)
    symbolsList = []
    for holding in holdings:
        symbolsList.append(holding["symbol"])

    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Obtain stock information
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must enter a symbol")
        if not lookup(symbol):
            return apology("Must enter a valid symbol")
        results = lookup(symbol)
        name = results["name"]
        price = results["price"]

        # Error checking
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("must sell a whole number of shares")
        tempRow = db.execute("SELECT * FROM holdings WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if shares < 1:
            return apology("must sell more than 0 shares")
        owned_shares = tempRow[0]["shares"]
        if shares > owned_shares:
            return apology("cannot sell more shares than owned")
        if (shares - int(shares)):
            return apology("must sell a whole number of shares")

        # Add transaction to 'transactions' table
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, timestamp) VALUES (?, ?, ?, ?, ?, ?)", user_id, symbol, name, -shares, price, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Update user's cash in 'users' table
        new_cash = user_cash + (shares * price)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        # Update user's holdings in 'holdings' table
        new_shares = owned_shares - shares
        db.execute("UPDATE holdings SET shares = ? WHERE user_id = ? AND symbol = ?", new_shares, user_id, symbol)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("sell.html", symbols = symbolsList)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
