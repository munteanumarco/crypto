from client import VotingClient
from flask import (
    Flask,
    render_template,
    redirect,
    request,
    session,
    url_for,
    flash,
)
from identification_client import IdentificationClient
from models.candidates import Candidate
from data_collection import DataCollection  # import the module you provided

app = Flask(__name__)
app.secret_key = "your-secret-key"  # required for session management


# Home page: links to registration and login
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

        # Create an instance of the identification client
        ident_client = IdentificationClient()
        response = ident_client.register_citizen(cnp, first_name, last_name)

        # Assuming the server returns a dict with status and PIN info.
        if isinstance(response, dict) and response.get("status") == "ERROR":
            flash(f"Registration error: {response.get('message')}")
        else:
            # On success, the server might return the PIN
            flash(
                f"Registration successful. Your PIN is: {response.get('pin', 'Check server logs for PIN')}"
            )
        return redirect(url_for("index"))

    return render_template("register.html")


# Login page: used to authenticate and then vote
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        cnp = request.form.get("cnp").strip()
        pin = request.form.get("pin").strip()

        # Create a VotingClient instance and try to retrieve the public key.
        voting_client = VotingClient(cnp=cnp, pin=pin)
        voting_client.get_public_key()

        if voting_client.public_key:
            # Store authentication details in the session
            session["cnp"] = cnp
            session["pin"] = pin
            flash("Login successful. You can now cast your vote.")
            return redirect(url_for("vote"))
        else:
            flash("Login failed. Check your CNP and PIN.")
    return render_template("login.html")


# Voting page: show candidates and submit vote
@app.route("/vote", methods=["GET", "POST"])
def vote():
    # Ensure user is logged in
    if "cnp" not in session or "pin" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    cnp = session["cnp"]
    pin = session["pin"]
    # Recreate a VotingClient instance using session credentials.
    voting_client = VotingClient(cnp=cnp, pin=pin)
    voting_client.get_public_key()

    # Define your candidates (could also come from a database or config)
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


@app.route("/results")
def results():
    try:
        # Load the vote statistics from the database
        data_collector = DataCollection("voting_db.sqlite")
        stats = data_collector.get_statistics()
        data_collector.close()
    except Exception as e:
        flash(f"Error collecting votes: {e}")
        return redirect(url_for("index"))

    # Map candidate codes to full names
    candidate_map = {
        "A": "Donald Trump",
        "B": "Boris Johnson",
        "C": "Angela Merkel",
    }
    # Replace keys if a mapping exists; otherwise, keep the original key.
    mapped_stats = {candidate_map.get(k, k): v for k, v in stats.items()}

    labels = list(mapped_stats.keys())
    values = list(mapped_stats.values())
    return render_template(
        "results.html", labels=labels, values=values, stats=mapped_stats
    )


if __name__ == "__main__":
    app.run(debug=True)
