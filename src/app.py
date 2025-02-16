from functools import wraps
from flask import (
    Flask,
    render_template,
    redirect,
    request,
    session,
    url_for,
    flash,
)
from werkzeug.security import check_password_hash
from identification_client import IdentificationClient
from models.candidates import Candidate
from data_collection import DataCollection
from models.db import UsersDb
from voting_client import VotingClient

app = Flask(__name__)
app.secret_key = "your-secret-key"


# Define the login_required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("cnp") or not session.get("pin"):
            flash("Please log in first.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Home page
@app.route("/")
def index():
    return render_template("index.html")


# Registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        cnp = request.form.get("cnp").strip()
        first_name = request.form.get("first_name").strip()
        last_name = request.form.get("last_name").strip()

        ident_client = IdentificationClient()
        response = ident_client.register_citizen(cnp, first_name, last_name)

        if isinstance(response, dict) and response.get("status") == "ERROR":
            flash(f"Registration error: {response.get('message')}")
        else:
            flash(
                f"Registration successful. Your PIN is: {response.get('pin', 'Check server logs for PIN')}"
            )
        return redirect(url_for("index"))

    return render_template("register.html")


# Login page for voters
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        cnp = request.form.get("cnp").strip()
        pin = request.form.get("pin").strip()

        voting_client = VotingClient(cnp=cnp, pin=pin)
        voting_client.get_public_key()

        if voting_client.public_key:
            session["cnp"] = cnp
            session["pin"] = pin
            flash("Login successful. You can now cast your vote.")
            return redirect(url_for("vote"))
        else:
            flash("Login failed. Check your CNP and PIN.")
    return render_template("login.html")


# Voting page protected by the login_required decorator
@app.route("/vote", methods=["GET", "POST"])
@login_required
def vote():
    cnp = session["cnp"]
    pin = session["pin"]
    voting_client = VotingClient(cnp=cnp, pin=pin)
    voting_client.get_public_key()

    candidates = [
        Candidate("A", "Donald Trump"),
        Candidate("B", "Boris Johnson"),
        Candidate("C", "Angela Merkel"),
    ]

    if request.method == "POST":
        selected_vote = request.form.get("vote")
        valid_codes = [c.code for c in candidates]
        if selected_vote in valid_codes:
            voting_client.cast_vote(selected_vote)
            flash("Vote cast successfully.")
            return redirect(url_for("thankyou"))
        else:
            flash("Invalid vote. Please try again.")

    return render_template("vote.html", candidates=candidates)


@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("index"))


# Protected results route (unchanged)
@app.route("/results")
def results():
    if not session.get("admin"):
        flash("Please log in as admin to access results.")
        return redirect(url_for("admin_login"))
    try:
        data_collector = DataCollection("voting_db.sqlite")
        stats = data_collector.get_statistics()
        data_collector.close()
    except Exception as e:
        flash(f"Error collecting votes: {e}")
        return redirect(url_for("index"))

    candidate_map = {
        "A": "Donald Trump",
        "B": "Boris Johnson",
        "C": "Angela Merkel",
    }
    mapped_stats = {candidate_map.get(k, k): v for k, v in stats.items()}
    labels = list(mapped_stats.keys())
    values = list(mapped_stats.values())
    return render_template(
        "results.html", labels=labels, values=values, stats=mapped_stats
    )


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        db = UsersDb()
        admin = db.get_admin(username)
        db.close()

        if admin and check_password_hash(admin[2], password):
            session["admin"] = True
            flash("Admin login successful.")
            return redirect(url_for("results"))
        else:
            flash("Invalid admin credentials.")
    return render_template("admin_login.html")


if __name__ == "__main__":
    app.run(debug=True)
