#===========================================================
# App Creation and Launch
#===========================================================

from flask import Flask, render_template, request, flash, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import html

from app.helpers.session import init_session
from app.helpers.db      import connect_db
from app.helpers.errors  import init_error, not_found_error
from app.helpers.logging import init_logging
from app.helpers.auth    import login_required
from app.helpers.time    import init_datetime, utc_timestamp, utc_timestamp_now


# Create the app
app = Flask(__name__)

# Configure app
init_session(app)   # Setup a session for messages, etc.
init_logging(app)   # Log requests
init_error(app)     # Handle errors and exceptions
init_datetime(app)  # Handle UTC dates in timestamps


#-----------------------------------------------------------
# Home page route
#-----------------------------------------------------------
@app.get("/")
def index():
    with connect_db() as client:
        # Get all the things from the DB
        sql = """
            SELECT code, name, description, manager
            FROM teams
            ORDER BY name ASC
        """
        params=[]
        result = client.execute(sql, params)
        teams = result.rows

        # And show them on the page
        return render_template("pages/home.jinja", teams=teams)


#-----------------------------------------------------------
# Team page route - Show details of a single thing
#-----------------------------------------------------------
@app.get("/team/<code>")
def show_one_thing(code):
    with connect_db() as client:
        # Get the team details from the DB, including the manager info
        sql = """
            SELECT teams.code,
                   teams.name AS team_name,
                   teams.description,
                   teams.website,
                   teams.manager,
                   users.name AS manager_name

            FROM teams
            JOIN users ON teams.manager = users.id

            WHERE teams.code=?
        """
        params = [code]
        result = client.execute(sql, params)

        # Did we get a result?
        if result.rows:
            # yes, so get the players and show it on the page
            team = result.rows[0]

            # Get the team players
            sql = """
                SELECT name, notes
                FROM players
                WHERE team=?
            """
            params = [code]
            result = client.execute(sql, params)
            players = result.rows

            return render_template("pages/team.jinja", team=team, players=players)

        else:
            # No, so show error
            return not_found_error()


#-----------------------------------------------------------
# Route for adding a team, using data posted from a form
# - Restricted to logged in users
#-----------------------------------------------------------
@app.post("/add")
@login_required
def add_a_thing():
    # Get the data from the form
    code  = request.form.get("code")
    name  = request.form.get("name")
    desc  = request.form.get("description")
    web   = request.form.get("website")

    # Sanitise the text inputs
    name = html.escape(name)
    desc = html.escape(desc)

    # Get the user id from the session
    user_id = session["user_id"]

    with connect_db() as client:
        # Add the thing to the DB
        sql = """
            INSERT INTO teams (code, name, description, website, manager)
            VALUES (?, ?, ?, ?, ?)
        """
        params = [code, name, desc, web, user_id]
        client.execute(sql, params)

        # Go back to the home page
        flash(f"Team '{name}' added", "success")
        return redirect("/")


#-----------------------------------------------------------
# Route for adding a player to a team, using data posted from a form
# - Restricted to logged in users
#-----------------------------------------------------------
@app.post("/add-player/<code>")
@login_required
def add_a_player(code):
    # Get the data from the form
    name  = request.form.get("name")
    notes = request.form.get("notes")

    # Sanitise the text inputs
    name  = html.escape(name)
    notes = html.escape(notes)

    with connect_db() as client:
        # Add the thing to the DB
        sql = """
            INSERT INTO players (name, notes, team)
            VALUES (?, ?, ?)
        """
        params = [name, notes, code]
        client.execute(sql, params)

        # Go back to the home page
        flash(f"Player '{name}' added", "success")
        return redirect(f"/team/{code}")


#-----------------------------------------------------------
# Route for deleting a team, Id given in the route
# - Restricted to logged in users
#-----------------------------------------------------------
@app.get("/delete/<int:id>")
@login_required
def delete_a_team(id):
    # Get the user id from the session
    user_id = session["user_id"]

    with connect_db() as client:
        # Delete the thing from the DB only if we own it
        sql = "DELETE FROM teams WHERE id=? AND user_id=?"
        params = [id, user_id]
        client.execute(sql, params)

        # Go back to the home page
        flash("Team and players deleted", "success")
        return redirect("/")







#-----------------------------------------------------------
# User registration form route
#-----------------------------------------------------------
@app.get("/register")
def register_form():
    return render_template("pages/register.jinja")


#-----------------------------------------------------------
# User login form route
#-----------------------------------------------------------
@app.get("/login")
@app.get("/login/")
def login_form():
    return render_template("pages/login.jinja")


#-----------------------------------------------------------
# Route for adding a user when registration form submitted
#-----------------------------------------------------------
@app.post("/add-user")
def add_user():
    # Get the data from the form
    name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")

    with connect_db() as client:
        # Attempt to find an existing record for that user
        sql = "SELECT * FROM users WHERE username = ?"
        params = [username]
        result = client.execute(sql, params)

        # No existing record found, so safe to add the user
        if not result.rows:
            # Sanitise the name
            name = html.escape(name)

            # Salt and hash the password
            hash = generate_password_hash(password)

            # Add the user to the users table
            sql = "INSERT INTO users (name, username, password_hash) VALUES (?, ?, ?)"
            params = [name, username, hash]
            client.execute(sql, params)

            # And let them know it was successful and they can login
            flash("Registration successful", "success")
            return redirect("/login")

        # Found an existing record, so prompt to try again
        flash("Username already exists. Try again...", "error")
        return redirect("/register")


#-----------------------------------------------------------
# Route for processing a user login
#-----------------------------------------------------------
@app.post("/login-user")
def login_user():
    # Get the login form data
    username = request.form.get("username")
    password = request.form.get("password")

    with connect_db() as client:
        # Attempt to find a record for that user
        sql = "SELECT * FROM users WHERE username = ?"
        params = [username]
        result = client.execute(sql, params)

        # Did we find a record?
        if result.rows:
            # Yes, so check password
            user = result.rows[0]
            hash = user["password_hash"]

            # Hash matches?
            if check_password_hash(hash, password):
                # Yes, so save info in the session
                session["user_id"]   = user["id"]
                session["user_name"] = user["name"]
                session["logged_in"] = True

                # And head back to the home page
                flash("Login successful", "success")
                return redirect("/")

        # Either username not found, or password was wrong
        flash("Invalid credentials", "error")
        return redirect("/login")


#-----------------------------------------------------------
# Route for processing a user logout
#-----------------------------------------------------------
@app.get("/logout")
def logout():
    # Clear the details from the session
    session.pop("user_id", None)
    session.pop("user_name", None)
    session.pop("logged_in", None)

    # And head back to the home page
    flash("Logged out successfully", "success")
    return redirect("/")

