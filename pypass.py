#!/usr/bin/env python3

import pandas as pd
from sqlalchemy import create_engine, text
import hashlib, binascii, os, pathlib, subprocess, datetime, getpass, argparse
from functools import wraps
from rich import print, inspect
from rich.console import Console
from rich.table import Table

def pretty(df:pd.DataFrame):
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    # Add columns to the table
    for col in df.columns:
        table.add_column(col)
    # Add rows to the table
    for _, row in df.iterrows():
        table.add_row(*[str(value) for value in row])

    return console, table

user_id: int = None
# Initialize the database engine
engine = create_engine('sqlite:///my_passwords.db')

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = input('Please Enter Authentication Username: ')
        password = getpass.getpass('Your Username Authentication password: ')
        if username and password and authenticate_user(username, password):
            return f(*args, **kwargs)
        else:
            return "Authentication failed, access denied."
    return decorated_function


def is_session_valid(user_id):
    """Check if the user's session is still valid."""
    query = "SELECT session_expires FROM users WHERE user_id = ?"
    result = pd.read_sql_query(query, con=engine, params=(user_id,))
    if not result.empty:
        session_expires = result.iloc[0]['session_expires']
        if datetime.datetime.now() < session_expires:
            print("Session is still valid.")
            return True
        else:
            print("Session has expired.")
    return False



def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

def authenticate_user(username, password):
    """Authenticate a user by their username and password."""
    try:
        # Query user data from SQLite database
        query = "SELECT user_id, hashed_password FROM users WHERE username = ?"
        result = pd.read_sql_query(query, con=engine, params=(username,))
        if not result.empty and verify_password(result.iloc[0]['hashed_password'], password):
            # Set the session expiration time
            session_expires = datetime.datetime.now() + datetime.timedelta(minutes=30)
            # Update the session expiration in the database
            update_query = text("UPDATE users SET session_expires = :session_expires WHERE user_id = :user_id")
            with engine.connect() as conn:
                # Pass parameters as a dictionary
                conn.execute(update_query, {'session_expires': session_expires, 'user_id': int(result.iloc[0]['user_id'])})
            print(f"User authenticated successfully. Session expires at {session_expires}")
            global user_id
            user_id = int(result.iloc[0]['user_id'])
            return True
        print('authentication failed')
        return False
    except Exception as e:
        print(f'Auth failed {e}')
        return False


def setup_user_table():
    with engine.connect() as conn:
        # Create the 'users' table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                session_expires DATETIME
            );
        """))

        # Create the 'passwords' table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS passwords (
                password_id INTEGER PRIMARY KEY,
                user_id INTEGER,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );
        """))


def register_user(username, password):
    """Register a new user with a hashed password."""
    hashed_password = hash_password(password)
    df = pd.DataFrame({'username': [username], 'hashed_password': [hashed_password]})
    df.to_sql('users', con=engine, if_exists='append', index=False)
    return "User registered successfully."


def generate_keys(private_key_file='private.pem', public_key_file='public.pem'):
    """Generate RSA private and public keys using OpenSSL."""
    try:
        # Generate private key
        subprocess.run(['openssl', 'genrsa', '-out', private_key_file, '2048'], check=True)
        print(f"Private key generated and saved to {private_key_file}")

        # Extract public key from private key
        subprocess.run(['openssl', 'rsa', '-in', private_key_file, '-outform', 'PEM', '-pubout', '-out', public_key_file], check=True)
        print(f"Public key generated and saved to {public_key_file}")

    except subprocess.CalledProcessError as e:
        print("An error occurred while generating keys:", str(e))

@auth_required
def get_pass(username):
    query = """
    SELECT encrypted_password
    FROM passwords
    WHERE username = ?
    """
    result = pd.read_sql_query(query, con=engine, params=(username,))
    return decrypt_data(result.values[0][0])


def encrypt_data(data):
    """Encrypt data using the public key and OAEP padding."""
    process = subprocess.Popen(
        ['openssl', 'pkeyutl', '-encrypt', '-pubin', '-inkey', 'public.pem', '-pkeyopt', 'rsa_padding_mode:oaep'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    encrypted_data, err = process.communicate(data.encode())
    if process.returncode != 0:
        raise Exception("Encryption failed:", err.decode())
    return encrypted_data

def decrypt_data(encrypted_data):
    """Decrypt data using the private key and OAEP padding."""
    process = subprocess.Popen(
        ['openssl', 'pkeyutl', '-decrypt', '-inkey', 'private.pem', '-pkeyopt', 'rsa_padding_mode:oaep'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    decrypted_data, err = process.communicate(encrypted_data)
    if process.returncode != 0:
        raise Exception("Decryption failed:", err.decode())
    return decrypted_data.decode()


@auth_required
def load_data(verbose: bool = False):
    """Load and display passwords related to a specific user from the SQLite database."""
    query = "SELECT * FROM passwords WHERE user_id = ?"
    df = pd.read_sql_query(query, con=engine, params=(user_id,))
    if verbose:
        # return print(df)
        console, table = pretty(df)
        return console.print(table)
    else:
        return print(df[['username']])

@auth_required
def add_password_for_user(username):
    password = getpass.getpass(f'Password entry for username {username}: ')  # Use getpass to hide the password input
    encrypted_password = encrypt_data(password)
    df = pd.DataFrame({'user_id': [user_id], 'username': username, 'encrypted_password': [encrypted_password]})
    df.to_sql('passwords', con=engine, if_exists='append', index=False)
    print("Password added successfully.")
    return

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Simple Commandline Password Manager using Pandas and SQLite")
    parser.add_argument('--add', '-a', nargs='*', help="Add new password entry. app.py -a website_username")
    parser.add_argument('--edit', '-e', nargs='*', help="Edit password entry based on username")
    parser.add_argument('--delete', '-d', nargs='*', help="Delete password entry for database")
    parser.add_argument('--table', '-t', action='store_true', help="View Table of password entries, passwords not visible")
    parser.add_argument('--get', '-g', nargs='*', help="Get and decrypt password")
    parser.add_argument('--keygen', '-k', action='store_true', help="Generate keys to encrypt password entries")
    parser.add_argument('--register', '-r', action='store_true', help="Register User Database")
    parser.add_argument('--verbose', '-v', action='store_true', help="Verbose output")
    
    args = parser.parse_args()
    
    if args.keygen:
        generate_keys()

    if args.add:
        add_password_for_user(args.add[0])
    
    if args.delete:
        pass

    if args.table:
        if args.verbose:
            verbose = True
        else:
            verbose = False
        load_data(verbose)

    if args.get:
        print(get_pass(args.get[0]))

    if args.register:
        if not pathlib.Path('my_passwords.db').exists():
            setup_user_table()
        username = input('Please Enter Username: ')
        password = getpass.getpass('Your password: ')
        register_user(username=username, password=password)
