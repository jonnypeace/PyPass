#!/usr/bin/env python3

import pandas as pd
from sqlalchemy import create_engine, text
import hashlib, binascii, os, pathlib, datetime, argparse, base64
from dataclasses import dataclass, field, asdict
from functools import wraps
from typing import Optional
from rich import print, inspect
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet


#################### Database Utils ####################

@dataclass
class UserTable:
    username: list[str]
    hashed_password: list[bytes]
    salt: list[bytes]
    edek: list[bytes]
    session_expires: Optional[datetime.datetime] = field(default=None, init=False)
    user_id: Optional[int] = field(default=None, init=False)
    
    def add_user_id(self, user_id: int):
        self.user_id = int(user_id )


@dataclass
class PassTable:
    name: list[bytes]
    username: list[bytes]
    password: list[bytes]
    category: list[bytes]
    notes: list[bytes]
    id: Optional[int] = field(default=None, init=False)
    user_id: Optional[int] = field(default=None, init=False)

    def add_id(self, id: int):
        self.id = int(id)
    
    def add_user_id(self, user_id: int):
        self.user_id = int(user_id)

class SQLManager:
    def __init__(self, db_url='sqlite:///py_pass.db'):
        self.engine = create_engine(db_url)
        self.user_table: Optional[UserTable] = None
        self.dek = None

    def setup_user_table(self):
        with self.engine.connect() as conn:
            # Create the 'users' table
            conn.execute(text("""
                            CREATE TABLE IF NOT EXISTS users (
                            user_id INTEGER PRIMARY KEY,
                            username TEXT UNIQUE NOT NULL,
                            hashed_password BLOB NOT NULL,
                            salt BLOB NOT NULL,
                            edek BLOB NOT NULL,
                            session_expires DATETIME
                            );
                            """))

            # Create the 'passwords' table
            conn.execute(text("""
                            CREATE TABLE IF NOT EXISTS passwords (
                            id INTEGER PRIMARY KEY,
                            user_id INTEGER,
                            name BLOB NOT NULL,
                            username BLOB NOT NULL,
                            password BLOB NOT NULL,
                            category BLOB NOT NULL,
                            notes BLOB NOT NULL,
                            FOREIGN KEY (user_id) REFERENCES users(user_id)
                            );
                            """))
            
    def register_user(self, data: UserTable):
        """Register a new user with a hashed password."""
        df = pd.DataFrame(asdict(data))
        try:
            df.to_sql('users', con=self.engine, if_exists='append', index=False)
            print("User registered successfully.")
        except Exception as e:
            print(f'Error: Username {data.username} may already exist in Database, please try again\n')
    
    def authenticate_user(self, username, password):
        """Authenticate a user by their username and password."""
        try:
            # Query user data from SQLite database
            query = "SELECT user_id, username, hashed_password, salt, edek FROM users WHERE username = ?"
            result = pd.read_sql_query(query, con=self.engine, params=(username,))
            if not result.empty and verify_password(result.iloc[0]['hashed_password'], password):
                self.user_table = UserTable(
                    username=result.iloc[0]['username'],
                    hashed_password=result.iloc[0]['hashed_password'],
                    salt=result.iloc[0]['salt'],
                    edek=result.iloc[0]['edek']
                )
                self.user_table.add_user_id(result.iloc[0]['user_id'])
                kek, _ = derive_kek(password, self.user_table.salt)
                self.dek = decrypt_dek(kek, self.user_table.edek)
                # Set the session expiration time
                session_expires = datetime.datetime.now() + datetime.timedelta(minutes=30)
                # Update the session expiration in the database
                update_query = text("UPDATE users SET session_expires = :session_expires WHERE user_id = :user_id")
                with self.engine.connect() as conn:
                    # Pass parameters as a dictionary
                    conn.execute(update_query, {'session_expires': session_expires, 'user_id': self.user_table.user_id})
                print(f"User authenticated successfully. Session expires at {session_expires}")
                return True
            print('authentication failed')
            return False
        except Exception as e:
            print(f'Auth failed {e}')
            return False
        
    def add_password_for_user(self, data: PassTable):
        data.add_user_id(self.user_table.user_id)
        df = pd.DataFrame(asdict(data))
        df.to_sql('passwords', con=self.engine, if_exists='append', index=False)
        print("Password added successfully.")
        return
    
    def load_table(self):
        """Load and display passwords related to a specific user from the SQLite database."""
        query = "SELECT * FROM passwords WHERE user_id = ?"
        df = pd.read_sql_query(query, con=self.engine, params=(self.user_table.user_id,))
        console, table = pretty(df)
        return console.print(table)
    
########################################################
        

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

########################################################


@dataclass
class Authentication:
    user_id: int = None


@dataclass
class DataManager:
    pass


#################### Encryption Utils ####################


def derive_kek(password: str, salt: bytes = None):
    # Salt should be securely stored and unique for each user in a real application
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    kek = kdf.derive(password.encode())
    return kek, salt

def encrypt_dek(kek):
    dek = Fernet.generate_key()
    fernet = Fernet(base64.urlsafe_b64encode(kek))
    edek = fernet.encrypt(dek)
    return edek, dek

def decrypt_dek(kek, encrypted_dek):
    fernet = Fernet(base64.urlsafe_b64encode(kek))
    dek = fernet.decrypt(encrypted_dek)
    return dek

def encrypt_data(dek, data):
    fernet = Fernet(dek)
    return fernet.encrypt(data.encode())

def decrypt_data(dek, encrypted_data):
    fernet = Fernet(dek)
    return fernet.decrypt(encrypted_data).decode()

# def auth_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         username = input('Please Enter Authentication Username: ')
#         password = getpass.getpass('Your Username Authentication password: ')
#         if username and password and authenticate_user(username, password):
#             return f(*args, **kwargs)
#         else:
#             return "Authentication failed, access denied."
#     return decorated_function


# def is_session_valid(user_id):
#     """Check if the user's session is still valid."""
#     query = "SELECT session_expires FROM users WHERE user_id = ?"
#     result = pd.read_sql_query(query, con=engine, params=(user_id,))
#     if not result.empty:
#         session_expires = result.iloc[0]['session_expires']
#         if datetime.datetime.now() < session_expires:
#             print("Session is still valid.")
#             return True
#         else:
#             print("Session has expired.")
#     return False

# @auth_required
# def get_pass(username):
#     query = """
#     SELECT encrypted_password
#     FROM passwords
#     WHERE username = ?
#     """
#     result = pd.read_sql_query(query, con=engine, params=(username,))
#     return decrypt_data(result.values[0][0])

# # @auth_required
# def add_password_for_user(username):
#     password = getpass.getpass(f'Password entry for username {username}: ')  # Use getpass to hide the password input
#     encrypted_password = encrypt_data(password)
#     df = pd.DataFrame({'user_id': [user_id], 'username': username, 'encrypted_password': [encrypted_password]})
#     df.to_sql('passwords', con=engine, if_exists='append', index=False)
#     print("Password added successfully.")
#     return


def setup_new_user(db: SQLManager, username, password)-> bytes:
    kek, salt = derive_kek(password)
    edek, dek = encrypt_dek(kek)
    hashed_password = hash_password(password)
    data = UserTable(username=[username], hashed_password=[hashed_password], salt=[salt], edek=[edek])
    db.register_user(data)


def pass_prompt(dek)-> PassTable:
    name: bytes = encrypt_data(dek, Prompt.ask('Website'))
    username: bytes = encrypt_data(dek, Prompt.ask('Username'))
    password_str: str = Prompt.ask('Password', password=True)
    confirm_password: str = Prompt.ask('Confirm Password', password=True)
    if password_str != confirm_password:
        print('Passwords do not match, try again')
        return False
    password: bytes = encrypt_data(dek, password_str)
    category: bytes = encrypt_data(dek, Prompt.ask('Category'))
    notes: bytes = encrypt_data(dek, Prompt.ask('Notes'))

    return PassTable(
        name=[name],
        username=[username],
        password=[password],
        category=[category],
        notes=[notes]
    )

def main():
    console = Console()
    console.print("Welcome to Secure Password Manager", style="bold blue")
    auth = False
    while auth is False:
        action = Prompt.ask("Choose action: [1. Add New User?, 2. Login?, 3. Quit?]")
        db = SQLManager()
        match action:
            case '1': # Add New User
                username = Prompt.ask("Enter your master username: ")
                password = Prompt.ask("Enter your master password: ", password=True)
                retype_password = Prompt.ask("Retype your master password: ", password=True)
                if password == retype_password:
                    if not pathlib.Path('py_pass.db').exists():
                        db.setup_user_table()

                setup_new_user(db=db, username=username, password=password)
        
            case '2': # Login
                username = Prompt.ask("Enter your master username")
                password = Prompt.ask("Enter your master password", password=True)
                if db.authenticate_user(username=username, password=password):
                    auth = True
        
            case '3':
                print('Exiting...')
                exit(0)
            case _:
                print('Unrecognised Option')
                continue

    inapp: bool = True
    while inapp:
        prompt = (
            'Choose Action:\n'
            '\n'
            '    1. Add New Password Entry\n'
            '    2. Get Password\n'
            '    3. See Password Table\n'
            '    4. Quit\n'
            '\n'
            'Selection'
        )
        action = Prompt.ask(prompt)
        match action:
            case '1':
                data: PassTable = pass_prompt(db.dek)
                if data is False:
                    continue
                db.add_password_for_user(data)
            case '2':
                pass
            case '3':
                db.load_table()
                Prompt.ask('Press Enter to continue...')
            case '4':
                print('Exiting...')
                inapp = False
            case _:
                print('Unrecognised Option')
                continue

 
if __name__ == '__main__':
    main()

    # parser = argparse.ArgumentParser(description="Simple Commandline Password Manager using Pandas and SQLite")
    # parser.add_argument('--add', '-a', nargs='*', help="Add new password entry. app.py -a website_username")
    # parser.add_argument('--edit', '-e', nargs='*', help="Edit password entry based on username")
    # parser.add_argument('--delete', '-d', nargs='*', help="Delete password entry for database")
    # parser.add_argument('--table', '-t', action='store_true', help="View Table of password entries, passwords not visible")
    # parser.add_argument('--get', '-g', nargs='*', help="Get and decrypt password")
    # parser.add_argument('--keygen', '-k', action='store_true', help="Generate keys to encrypt password entries")
    # parser.add_argument('--register', '-r', action='store_true', help="Register User Database")
    # parser.add_argument('--verbose', '-v', action='store_true', help="Verbose output")
    # parser.add_argument('--username', '-u', nargs='*', help="For automation, username can be supplied in terminal")
    # parser.add_argument('--password', '-p', nargs='*', help="For automation, password can be supplied in the terminal")
    # parser.add_argument('--config-file', '-c', nargs='*', help="For automation, yaml or json can be supplied with user credentials")
    
    
    # args = parser.parse_args()
    
    # if args.keygen:
    #     generate_keys()

    # if args.add:
    #     add_password_for_user(args.add[0])
    
    # if args.delete:
    #     pass

    # if args.table:
    #     if args.verbose:
    #         verbose = True
    #     else:
    #         verbose = False
    #     load_data(verbose)

    # if args.get:
    #     print(get_pass(args.get[0]))

    # if args.register:
    #     if not pathlib.Path('py_pass.db').exists():
    #         setup_user_table()
    #     username = input('Please Enter Username: ')
    #     password = getpass.getpass('Your password: ')
    #     register_user(username=username, password=password)
