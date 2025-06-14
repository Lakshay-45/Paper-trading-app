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
    """Show portfolio of stocks"""

    # Current user username
    username = db.execute(
        "SELECT username FROM users WHERE id = ?", session.get("user_id")
    )

    # Current shares data of user
    shares = db.execute(
        "SELECT symbol, shares FROM shares WHERE username = ?", username[0]["username"]
    )

    # List for stock prices and total value of holding
    stock_price = {}
    total_value = {}

    # Looping over all stocks owned by user
    for i in range(0, len(shares)):
        current = lookup(shares[i]["symbol"])
        stock_price[shares[i]["symbol"]] = current["price"]
        total_value[shares[i]["symbol"]] = (
            stock_price[shares[i]["symbol"]] * shares[i]["shares"]
        )

    # User's current balance
    cash = db.execute(
        "SELECT cash FROM users WHERE username = ?", username[0]["username"]
    )

    stock_total = 0

    # Calculating stocks total value
    for i in range(0, len(total_value)):
        stock_total += total_value[shares[i]["symbol"]]

    grand_total = stock_total + cash[0]["cash"]

    return render_template(
        "index.html",
        stocks=shares,
        stock_price=stock_price,
        total_value=total_value,
        cash=cash[0],
        gt=grand_total,
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached via POST
    if request.method == "POST":
        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("Must enter the stock symbol", 400)

        symbol = lookup(request.form.get("symbol"))
        shares = request.form.get("shares")

        # Ensure positive integral no. of shares were entered
        if shares.isdigit():
            shares = int(shares)

        else:
            return apology("Please enter valid no. of shares", 400)

        # Ensure symbol is correct
        if not symbol:
            return apology("Must enter valid symbol", 400)

        # Checking how much cash user has
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))

        # Ensure user can afford the shares
        if symbol["price"] * shares > cash[0]["cash"]:
            return apology("Sorry, you can't afford the shares", 403)

        # Retriving username of current user
        username = db.execute(
            "SELECT username FROM users WHERE id = ?", session.get("user_id")
        )

        # Checking if the user already own the stock
        share = db.execute(
            "SELECT shares FROM shares WHERE symbol = ? AND username = ?",
            symbol["symbol"],
            username[0]["username"],
        )

        if len(share) == 0:
            # Updating the user's purchase in database
            db.execute(
                "INSERT INTO shares (username, symbol, price, shares) VALUES (?, ?, ?, ?)",
                username[0]["username"],
                symbol["symbol"],
                symbol["price"],
                shares,
            )

        else:
            shares += share[0]["shares"]
            db.execute(
                "UPDATE shares SET shares = ? WHERE username = ? AND symbol = ?",
                shares,
                username[0]["username"],
                symbol["symbol"],
            )

        cur_cash = cash[0]["cash"] - (symbol["price"] * int(request.form.get("shares")))

        # Updating user's cash
        db.execute(
            "UPDATE users SET cash = ? WHERE username = ?",
            cur_cash,
            username[0]["username"],
        )

        # Updating the history of user
        db.execute(
            "INSERT INTO history (username, trans_type, symbol, price, shares) VALUES (?, ?, ?, ?, ?)",
            username[0]["username"],
            "Bought",
            request.form.get("symbol"),
            symbol["price"],
            int(request.form.get("shares")),
        )

        return redirect("/")

    # User reached via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Showing user history
    history = db.execute(
        "SELECT trans_type, symbol, price, shares, time FROM history, users WHERE users.username = history.username AND id = ?",
        session.get("user_id"),
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

    # User reached via POST
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        # Checking if the symbol entered is valid
        if not quote:
            return apology("Enter valid stock symbol", 400)

        return render_template("quoted.html", quote=quote)

    # User reached via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached via POST
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Must provide username", 400)

        # Ensure username isn't already in database
        data = db.execute("SELECT username FROM users")

        # Looping over all the usernames
        for username in data:
            # Returning apology is username already exists
            if username["username"] == request.form.get("username"):
                return apology("Username already exists", 400)

        # Ensure password was entered
        if not request.form.get("password"):
            return apology("Must enter password", 400)

        # Ensure confirm password was entered
        if not request.form.get("confirmation"):
            return apology("Must confirm password", 400)

        # Ensure password nd confirmation are same
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Password and confirmation must be same", 400)

        # Generating password hash
        hash = generate_password_hash(request.form.get("password"))

        # Inserting new user
        db.execute(
            "INSERT INTO users (username ,hash) VALUES (?, ?)",
            request.form.get("username"),
            hash,
        )

        return redirect("/")

    # User reached via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Stocks currently owned by user
    stocks = db.execute(
        "SELECT symbol, shares FROM users, shares WHERE users.username = shares.username AND id = ?",
        session.get("user_id"),
    )

    # Converting stocks to a list
    stocks_owned = []

    for stock in stocks:
        stocks_owned.append(stock["symbol"])

    # User reached via POST
    if request.method == "POST":
        # Ensure user selected a stock
        if not request.form.get("symbol"):
            return apology("Please select a stock to sell", 400)

        # Ensure user owns the stock
        if request.form.get("symbol") not in stocks_owned:
            return apology("You don't own any of the selected stocks", 400)

        # Locating the posn of stock to sell
        i = -1
        for j in range(0, len(stocks)):
            if request.form.get("symbol") == stocks[j]["symbol"]:
                i = j

        # Ensure user input positive no of stocks
        if int(request.form.get("shares")) < 0:
            return apology("Please enter positive no. of stocks to sell", 400)

        # Ensure user owns that many shares to sell
        if int(request.form.get("shares")) > stocks[i]["shares"]:
            return apology("You don't own enough shares", 400)

        # Ensuring current price of the stock
        curr = lookup(request.form.get("symbol"))

        # Total value earned
        total = curr["price"] * int(request.form.get("shares"))

        # Cash already in hand
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))

        # Total cash after selling
        value = cash[0]["cash"] + total

        # Updating user cash
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", value, session.get("user_id")
        )

        # Calculating remaining shares
        shares_rem = stocks[i]["shares"] - int(request.form.get("shares"))

        # Finding username
        username = db.execute(
            "SELECT username FROM users WHERE id = ?", session.get("user_id")
        )

        # Checking if user owns any shares after selling
        if shares_rem == 0:
            # Deleting the shares row
            db.execute(
                "DELETE FROM shares WHERE username = ? AND symbol = ?",
                username[0]["username"],
                request.form.get("symbol"),
            )

        else:
            # Updating shares owned
            db.execute(
                "UPDATE shares SET shares = ? WHERE username = ? AND symbol = ?",
                shares_rem,
                username[0]["username"],
                request.form.get("symbol"),
            )

        # Updating the history of user
        db.execute(
            "INSERT INTO history (username, trans_type, symbol, price, shares) VALUES (?, ?, ?, ?, ?)",
            username[0]["username"],
            "Sold",
            request.form.get("symbol"),
            curr["price"],
            int(request.form.get("shares")),
        )

        return redirect("/")

    # User reached via GET
    else:
        return render_template("sell.html", stocks=stocks)


@app.route("/money", methods=["GET", "POST"])
@login_required
def money():
    # Figuring out current money in account
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))

    # User reached via POST
    if request.method == "POST":
        # Ensure positive amount was entered
        if int(request.form.get("money")) < 0:
            return apology("Please enter a positive amount of money", 403)

        money = cash[0]["cash"] + int(request.form.get("money"))

        # Updating user's cash
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", money, session.get("user_id")
        )

        return redirect("/")

    # User reached via GET
    else:
        return render_template("money.html", cash=cash[0])
