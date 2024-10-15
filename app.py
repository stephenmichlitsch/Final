from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, CipherSuite, lockout_user, lockout_check, generate_password, check_password_strength

# Configure application
app = Flask(__name__)

# Load the encryption key and set up the cipher suite # Note Chat GPT helped me create the logic of setting up a ecrpytion enviroment I ended up creating it as a class and designing it's functions in a separate file (helpers.py)
cipher = CipherSuite()

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///security.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # Gets user id
    user_id = session['user_id'] 
    # Gets user name
    username = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])
    # Gets a dictionary of the users accounts
    user_accounts = db.execute("SELECT account_name, password FROM accounts WHERE user_id = ?", user_id)
    # This variable my be redundent might go through and change code to get rid of this and just use  user_aacounts
    accounts = db.execute("SELECT * FROM accounts WHERE user_id = ?", session["user_id"])
    
    # Decrypts passwords for the user to edit
    for acc in user_accounts:
        acc["password"] = cipher.decrypt(acc["password"])
    
    if not username:
        flash("No user name found try logging in.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # If user selects update
        if action == 'update':
            # Checks to make sure user selected an account to update
            if not request.form.get('account_id'):
                flash("Must select an account to update.", 'error')
                return redirect(url_for('index'))
            # Checks to make sure user typed in a new password to update to
            if not request.form.get('update_password'):
                flash("Need a need password for this account.", 'error')
                return redirect(url_for('index'))
            # Executes the change in the data base and encrypts the updated password
            encrypted_password = cipher.encrypt(request.form.get('update_password'))
            db.execute("UPDATE accounts SET password = ? WHERE id = ?", encrypted_password, request.form.get('account_id'))
            flash("Password updated", 'success')
            return redirect(url_for('index'))
            
        # If user selects remove
        elif action == 'remove':

            if not request.form.get('account_id'):
                flash("Must select an account to delete.", 'error')
                return redirect(url_for('index'))
            db.execute("DELETE FROM accounts WHERE id = ?", request.form.get('account_id'))
            flash("Account deleted.", 'success')
            return redirect(url_for('index'))
            
        elif action == 'add_password':
            
            if not request.form.get('new_account'):
                flash("Must enter the name of the new account.", 'error')
                return redirect(url_for('index'))
            # Checks for a password for the new account
            if not request.form.get('new_password'):
                flash("Must enter a password for a new account.", 'error')
                return redirect(url_for('index'))
            # Puts user account name and new password into variables
            new_account = request.form.get('new_account')
            encrypted_password = cipher.encrypt(request.form.get('new_password'))
            new_password = encrypted_password
            # Executes the new variables into the database
            db.execute("INSERT INTO accounts (account_name, password, user_id) VALUES (?, ?, ?)", new_account, new_password, session["user_id"])
            flash("New account added.", 'success')
            return redirect(url_for('index'))
            
        elif action == 'generate_password':
            generated_password = generate_password()
            return render_template('/index.html', generated_password=generated_password, username=username[0]['username'], accounts=accounts, user_accounts=user_accounts)
        
        return render_template('/index.html', accounts=accounts)
    
    else:
        accounts = db.execute("SELECT * FROM accounts WHERE user_id = ?", session['user_id'])
        return render_template('/index.html', accounts=accounts, username=username[0]['username'], user_accounts=user_accounts)
    

@app.route("/login", methods=["GET", "POST"])
def login():
    
    # Forget any user_id
    session.clear()
    
    
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
    
    # Ensure username was submitted
        if not username or not password:
            print("Missing User name or password.")
            flash("Must enter user name and password", 'error')
            return render_template("/login.html")

        # Query database for username
        rows = db.execute(
            "SELECT id, password_hash, login_attempts FROM users WHERE username = ?", username
        )
        
        
        # Checks if user exsist
        if not rows:
            flash("User not found", "error")
            return render_template("/login.html")
        
        # Gets user_id
        user_id = rows[0]["id"]

        # First checks if user input has been locked out 
        if lockout_check(user_id):
            print("Still locked out.")
            db.execute("UPDATE users SET login_attempts = 0 WHERE id = ?", user_id)
            flash(f"{username} is still locked out.", 'error')
            return render_template("/login.html")
        
        # Ensure username exists and password is correct    
        if len(rows) != 1 or not check_password_hash(
            rows[0]["password_hash"], password
        ):
            
            # Updates attempts to add one more
            db.execute("UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?", user_id)
            
            # Gets attempts for user
            a = db.execute("SELECT login_attempts FROM users WHERE id = ?", user_id)
            attempts = a[0]["login_attempts"]
            print("Atttempts:", attempts)
            print("User ID:", user_id)
            
            
            # Checks how many attempts the user has made 
            if int(attempts) >= 5:
                print("Iniside Attempts")
                if not lockout_check(user_id):
                    print("Locked out.")
                    lockout_user(user_id)
                    db.execute("UPDATE users SET login_attempts = 0 WHERE id = ?", user_id)
                    flash(f"{username} has been locked out for 24 hours.", 'error')
                    return render_template("/login.html")
            elif int(attempts) == 4:
                print("Fourth Attempt warning.")
                flash("One more attempt remaining before being locked out.", 'error')
                return render_template("/login.html")
            print("Outside Attempts.")    
            flash("Incorrect user name or password", "error")
            return render_template("/login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        
        db.execute("UPDATE users SET login_attempts = 0 WHERE id = ?", rows[0]["id"])

        # Render the template for index.html on a successful login
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


@app.route("/register", methods=["GET", "POST"])
def register():
    
    if request.method == 'POST':
        
        # Checks if a user name was submited
        if not request.form.get('username'):
            flash("Must enter a valid user name")
            return redirect(url_for('register'))
        
        # Checks if a password was submited
        if not request.form.get('password'):
            flash("Must enter a valid password")
            return redirect(url_for('register'))
        
        # Checks to confirm passoword with user
        if not request.form.get('confirm_password'):
            flash("Must confirm your password")
            return redirect(url_for('register'))
        
        # Get vairables username, password and confirmation
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirm_password")
        
        
        # Gets a variable from the database to check if the username does not already exsit
        user_check = db.execute("SELECT username FROM users WHERE username = ?", username)
        
        # Hashes password to secure it in the database 
        hashed_password = generate_password_hash(password)
        
        # Checks if user name is not already in the data base
        try: 
            if user_check:
                flash('User name already exists', 'error')
                return redirect(url_for('register'))
        except:
            flash('Error', 'error')
            return redirect(url_for('register'))
        
        # Checks to make sure the password and the confirmation passwords match 
        if password != confirmation:
            flash('Your passwords do not match', 'error')
            return redirect(url_for('register'))
        
        # If no errors then we insert the users new data into the data base and return to login
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, hashed_password)
        
        return redirect("/login")
    
    else:
        return render_template("register.html")
        
        
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    # Checks to make sure they typed in a password and username
    if request.method == "POST":
        if not request.form.get("new_password"):
            flash("Must enter a new password.", 'error')
            return redirect(url_for("change_password"))
        elif not request.form.get("confirmation"):
            flash("Must confirm your new password.", 'error')
            return redirect(url_for("change_password"))
        elif not request.form.get("username"):
            flash("Must enter user name.", 'error')
            return redirect(url_for("change_password"))

        # Gets input from user
        username = request.form.get("username")
        password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Uses query to point cursor to the username
        cursor = db.execute("SELECT username FROM users WHERE username = ?", username)
        if cursor:
            existing_username = cursor[0]['username']
        elif not cursor:
            flash("User name does not exists.", 'error')
            return redirect(url_for("change_password"))

        # Checks if username exists
        if existing_username:
            hashed_password = generate_password_hash(password)

            # Checks to make sure passowrds do not match
            if password != confirmation:
                flash("Passwords do not match.", 'error')
                return redirect(url_for("change_password"))

            # Uses query to point cursor to the hash password
            cursor = db.execute("SELECT password_hash FROM users WHERE username = ?", username)
            if cursor:
                existing_password = cursor[0]['password_hash']

            # Check if the password entered matches the old password
            if check_password_hash(existing_password, request.form.get("new_password")):
                flash("You already have this password.", 'error')
                return redirect(url_for("change_password"))

    
            db.execute("UPDATE users SET password_hash = ? WHERE username = ?", hashed_password, username)
           

            # If password change works then return to login page
        return redirect("/login")


    else:
        return render_template("change_password.html")
    
@app.route('/check_password_strength', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data['password']
    strength = check_password_strength(password)
    return jsonify({'strength': strength})
    