
import os
import sqlite3
from contextlib import closing
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

# SQLite DB Path
DB_PATH = "finance.db"

def execute_query(query, params=(), fetchone=False, fetchall=False, commit=False):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        with closing(conn.cursor()) as cursor:
            cursor.execute(query, params)
            if commit:
                conn.commit()
            if fetchone:
                return cursor.fetchone()
            if fetchall:
                return cursor.fetchall()

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    userInfo = execute_query("SELECT * FROM users WHERE id = ?", (session["user_id"],), fetchall=True)
    transactions = execute_query("SELECT * FROM transactions WHERE user_id = ?", (session["user_id"],), fetchall=True)
    return render_template("index.html", user=userInfo[0]["username"], transactions=transactions, cash=usd(userInfo[0]["cash"]))

@app.route("/addCash", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        cash = request.form.get("newCash")
        if not cash:
            return apology("Enter a positive and whole amount")
        userCash = execute_query("SELECT cash FROM users WHERE id = ?", (session["user_id"],), fetchone=True)["cash"]
        cash = int(cash)
        userCash += cash
        execute_query("UPDATE users SET cash = ? WHERE id = ?", (userCash, session["user_id"]), commit=True)
        return redirect("/")
    else:
        return render_template("addCash.html")

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stockAmount = request.form.get("shares")
        if not stockAmount or not symbol or not stockAmount.isdigit():
            return apology("Must enter a valid symbol and stock amount")
        symbol = symbol.upper()
        stockInfo = lookup(symbol)
        if stockInfo is None:
            return apology("Invalid Symbol")
        cashOnHand = execute_query("SELECT cash FROM users WHERE id = ?", (session["user_id"],), fetchone=True)["cash"]
        stockAmount = int(stockAmount)
        if stockAmount < 0:
            return apology("Stock amount must be positive and whole")
        cashTotal = stockAmount * stockInfo["price"]
        if cashOnHand > cashTotal:
            execute_query("INSERT INTO transactions (user_id, symbol, total, price, shares, method) VALUES (?, ?, ?, ?, ?, ?)",
                          (session["user_id"], symbol, cashTotal, stockInfo["price"], stockAmount, "BUY"), commit=True)
            cashOnHand -= cashTotal
            execute_query("UPDATE users SET cash = ? WHERE id = ?", (cashOnHand, session["user_id"]), commit=True)
            return redirect("/")
        else:
            return apology("You dont have enough Cash")
    else:
        cashOnHand = execute_query("SELECT cash FROM users WHERE id = ?", (session["user_id"],), fetchone=True)
        return render_template("buy.html", cash=usd(cashOnHand["cash"]))

@app.route("/history")
@login_required
def history():
    transactions = execute_query("SELECT * FROM transactions WHERE user_id = ?", (session["user_id"],), fetchall=True)
    return render_template("history.html", transactions=transactions)

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        rows = execute_query("SELECT * FROM users WHERE username = ?", (request.form.get("username"),), fetchall=True)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()
    if request.method == "POST":
        name = request.form.get("username")
        if not name:
            return apology("Enter Username")
        password = request.form.get("password")
        if not password:
            return apology("Enter Password")
        confirmation = request.form.get("confirmation")
        if not confirmation or password != confirmation:
            return apology("Re-enter Password")
        password = generate_password_hash(password)
        try:
            execute_query("INSERT INTO users (username, hash) VALUES (?, ?)", (name, password), commit=True)
        except:
            return apology("Username already Taken")
        row = execute_query("SELECT * FROM users WHERE username = ?", (name,), fetchall=True)
        session["user_id"] = row[0]["id"]
        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    symbols_user = execute_query("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0",
                                 (session["user_id"],), fetchall=True)
    if request.method == "POST":
        symbol = request.form.get("userStocks")
        shares = request.form.get("shares")
        if not symbol or not shares or not shares.isdigit():
            return apology("Enter Valid symbol or shares")
        symbol = symbol.upper()
        shares = int(shares)
        stockInfo = lookup(symbol)
        if stockInfo is None:
            return apology("Symbol Does Not Exist")
        if shares < 0:
            return apology("Share Not Allowed")
        cashTotal = shares * stockInfo["price"]
        userCash = execute_query("SELECT cash FROM users WHERE id = ?", (session["user_id"],), fetchone=True)["cash"]
        currentShares = execute_query("SELECT SUM(shares) as total FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol",
                                      (session["user_id"], symbol), fetchone=True)["total"]
        if shares > currentShares:
            return apology("You don't have this amount Of Shares")
        userCash += cashTotal
        execute_query("UPDATE users SET cash = ?  WHERE id = ?", (userCash, session["user_id"]), commit=True)
        execute_query("INSERT INTO transactions (user_id, symbol, total, price, shares, method) VALUES (?, ?, ?, ?, ?, ?)",
                      (session["user_id"], symbol, cashTotal, stockInfo["price"], shares, "SELL"), commit=True)
        return redirect("/")
    else:
        return render_template("sell.html", userStocks=[row["symbol"] for row in symbols_user])


@app.route("/api/quote", methods=["POST"])
@login_required
def api_quote():
    symbol = request.json.get("symbol", "").upper()
    if not symbol:
        return {"error": "Missing symbol"}, 400
    stock = lookup(symbol)
    if stock is None:
        return {"error": "Invalid symbol"}, 404
    return {"symbol": stock["symbol"], "price": stock["price"]}



if __name__ == "__main__":
    app.run(debug=True)
