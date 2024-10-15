import os
import secrets
import string
import time

from cs50 import SQL
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import redirect, render_template, request, session
from functools import wraps

# Load enviroment variable from key.env file
load_dotenv('key.env')

# A dictionary of users who are locked out
lockout_dict = {}

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///security.db")


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


# Chat GPT helped me with the logic of creating this class though the class was my idea Chat helped me understand the functions inside of Fernet and how to use them. Also I understand that generally you would simply generate a key and manually type this in the key.env but for demostration sake it felt easier to simply build a class to show I understood how it worked and it also made it easier to create my encryption and decryption functions with in the class
class CipherSuite:
    """Class for managing encryption and decryption."""

    # Initalizes an instance to be used inside the class only to generate a key 
    def __init__(self):
        # Creates a key using the load or generate key function I created
        self.key = self.load_or_generate_key()
        # Creates a Fernet instance for encrypting and decrypting with in the class
        self.cipher_suite = Fernet(self.key)

    # Generates the random key to be initalized in the class
    def load_or_generate_key(self):
        # Checks the encryption key enviroment variable
        key_env = os.getenv('ENCRYPTION_KEY')
        # If key does exsist return key encoding it
        if key_env:
            # Encoding simply means it converts the key into 1's and 0's 
            # Fernet requires that the key be encoded for encyption and decryption
            return key_env.encode()
        # Else we generate a new key to be written into enviroment variable
        else:
            # When Fernet.generate_key is given to new_key it is encoded
            new_key = Fernet.generate_key()
            # Then we write the new key into key.env for safe keeping
            with open('key.env', 'w') as f:
                f.write(f"ENCRYPTION_KEY={new_key.decode()}")
            # Return the new_key so other functions with in the class can use the key for encrpytion or decryption
            return new_key
        

    # Ecrypts data
    def encrypt(self, data):
        return self.cipher_suite.encrypt(data.encode())
    

    # Decrypts encrypted data
    def decrypt(self, encrypted_data):
        return self.cipher_suite.decrypt(encrypted_data).decode()
    
    
# Puts a uesr in a lockout list in the data base
def lockout_user(user_id):
    # Grabs current time 
    lockout_time = int(time.time())
    # Sets a release time 
    release_time = lockout_time + (24 * 3600)
    # Stores user id and release time in the data base
    db.execute("INSERT INTO lockouts (user_id, release_time) VALUES (?, ?)", user_id, release_time)
    
    
# Checks the data base release time for said user 
def lockout_check(user_id):
    # Gets current time
    current_time = int(time.time())
    # Grabs the release time fro mthe database and checks to make sure it's not empty
    r = db.execute("SELECT release_time FROM lockouts WHERE user_id = ?", user_id)
    try:
        release_time = r[0]['release_time']
    except:
        return False
    
    # If we have a release time then we check if it is that time
    if release_time:
        if current_time < release_time:
            return True
        else:
            db.execute("DELETE FROM lockouts WHERE user_id = ?", user_id)
            return False
        
        
# Generates a password for user to use
def generate_password(length=32):
    alphabet = string.ascii_letters + string.digits + "()!@#$%&?"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


# Checks the strength of a users password
def check_password_strength(password):
    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in "!@#$%^&*()_+-=[]{};:'\"\\|,.<>/?~" for char in password)
    length_score = len(password) >= 8

    strength_score = (has_uppercase + has_lowercase + has_digit + has_special + length_score) / 5.0

    if strength_score >= 0.75:
        return "Strong"
    elif strength_score >= 0.5:
        return "Medium"
    else:
        return "Weak"