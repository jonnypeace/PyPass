#!/usr/bin/env python3

from numpy.core.fromnumeric import argsort
import pandas as pd
from pandas.core.api import DataFrame
from sqlalchemy import create_engine, text
import hashlib, binascii, os, pathlib, datetime, argparse, base64, getpass, sys, pyclip, threading, time, secrets, string
from threading import Timer
from queue import Queue
from dataclasses import dataclass, field, asdict
from functools import wraps
from typing import Optional
from rich import print, inspect
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.pretty import pprint
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.theme import Theme
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from prompt_toolkit.completion import FuzzyWordCompleter
from prompt_toolkit import prompt as fuzzy_prompt
from copy import copy
from navigation import file_system_nav


#################### Clipboard #########################

def user_interaction(console, q):
    console.print("    Press ENTER to stop the countdown and clear clipboard early...\n\n", style='purple')
    input()
    q.put('stop')

def copy_to_clipboard(console, text, timeout=30):
    q = Queue()
    pyclip.copy(text)
    user_thread = threading.Thread(target=user_interaction, args=(console, q))
    user_thread.start()
    
    with Live(Panel(f"    [purple]Clipboard will be cleared in {timeout} seconds...[/purple]", title="Clipboard Timeout", border_style='green'), console=console, refresh_per_second=1) as live:
        for i in range(timeout-1, 0, -1):
            time.sleep(1)
            if not q.empty():
                live.update(Panel("    [purple]Clipboard clearing stopped by user[/purple]", title="Clipboard Timeout", border_style='green'))
                pyclip.clear()
                user_thread.join()
                return
            live.update(Panel(f"    [purple]{i} seconds until clipboard is cleared[/purple]", title="Clipboard Timeout", border_style='green'))
        else:
            live.update(Panel("    [purple]Clipboard cleared after timeout. Press ENTER to Continue[/purple]", title='Clipboard Timeout', border_style='green'))
            pyclip.clear()
            user_thread.join()
            return

#################### Database Utils ####################

@dataclass
class UserTable:
    username: list[str]
    hashed_password: list[str]
    salt: list[bytes]
    edek: list[bytes]
    session_expires: Optional[datetime.datetime] = field(default=None, init=False)
    user_id: Optional[int] = field(default=None, init=False)
    
    def add_user_id(self, user_id: int):
        self.user_id = int(user_id )


@dataclass
class PassTable:
    name: list[bytes]|bytes
    username: list[bytes]|bytes
    password: list[bytes]|bytes
    category: list[bytes]|bytes
    notes: list[bytes]|bytes
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
                            hashed_password TEXT NOT NULL,
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
                            name BLOB,
                            username BLOB,
                            password BLOB,
                            category BLOB,
                            notes BLOB,
                            FOREIGN KEY (user_id) REFERENCES users(user_id)
                            );
                            """))
            
    def register_user(self, data: UserTable):
        """Register a new user with a hashed password."""
        df = pd.DataFrame(asdict(data))
        try:
            df.to_sql('users', con=self.engine, if_exists='append', index=False)
            return True
        except Exception as e:
            return False
    
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
                return True
            print('    Authentication failed')
            return False
        except Exception as e:
            print(f'Auth failed {e}')
            return False
        
    def add_password_for_user(self, data: PassTable):
        data.add_user_id(self.user_table.user_id)
        df = pd.DataFrame(asdict(data))
        df.to_sql('passwords', con=self.engine, if_exists='append', index=False)
        print("    Password added successfully.")
        return

    def update_password_for_user(self, data: PassTable, id: int):
        query = text('''
        UPDATE passwords 
        SET name = :name, username = :username, password = :password, category = :category, notes = :notes
        WHERE id = :id AND user_id = :user_id
        ''')
        data.add_user_id(self.user_table.user_id)
        data.add_id(id)
        with self.engine.connect() as conn:
            conn.execute(query, asdict(data))
            conn.commit()
            print("    Password updated successfully.")
        return

    
    def file_to_sql(self, df: pd.DataFrame):
        df['user_id'] = self.user_table.user_id
        df = df.sort_values(by='name')
        df.reset_index(drop=True)
        cols = ['name', 'username', 'password', 'category', 'notes']
        for col in cols:
            # Ensure that the data is in bytes, then decrypt
            df[col] = df[col].apply(lambda x: encrypt_data(self.dek, str(x)))
        df.to_sql('passwords', con=self.engine, if_exists='append', index=False)
        print('    File Uploaded into Database Successfully')

    def get_df(self):
        query = "SELECT * FROM passwords WHERE user_id = ?"
        df = pd.read_sql_query(query, con=self.engine, params=(self.user_table.user_id,))
        return df

    def load_table(self, console):
        """Load and display passwords related to a specific user from the SQLite database."""
        df = self.get_df()
        decrypted_df = df
        cols = ['name', 'username', 'category', 'notes']
        for col in cols:
            # Ensure that the data is in bytes, then decrypt
            decrypted_df[col] = df[col].apply(lambda x: decrypt_data(self.dek, x) if isinstance(x, bytes) else x)
        return print_paginated_table(console, decrypted_df, 10)

    def get_pass(self, name):
        query = """
        SELECT password
        FROM passwords
        WHERE name = ?
        AND user_id = ?
        """
        try:
            result = pd.read_sql_query(query, con=self.engine, params=(name, self.user_table.user_id,))
            if not result.empty:
                password = result.values[0][0]
                return decrypt_data(self.dek, password)
            else:
                return None  # Or raise an exception, or handle the "not found" case as appropriate
        except Exception as e:
            print(f"An error occurred: {e}")
            # Optionally, handle or re-raise the error depending on your error handling strategy
            return None


    def delete_data_entry(self, entry: list):
        query = text("DELETE FROM passwords WHERE id = :id AND user_id = :user_id")
        with self.engine.connect() as conn:
            with conn.begin():
                for id in entry:
                    try:
                        # Ensure the parameters are passed as a tuple within a list
                        conn.execute(query, {'id': id, 'user_id': self.user_table.user_id})
                    except Exception as e:
                        print(f"    An error occurred: {e}")  # Debugging output

    def data_entry_by_id(self, id: list[int], console: Console):
        query = """
        SELECT *
        FROM passwords
        WHERE id = ?
        AND user_id = ?
        """
        try:
            result = pd.read_sql_query(query, con=self.engine, params=(id[0], self.user_table.user_id,))
            if not result.empty:
                decrypted_data = result.map(lambda x: decrypt_data(self.dek, x) if isinstance(x, bytes) else x)
                return rich_table(decrypted_data)
            else:
                print(f'    No result found with database query, id: {id}, result: {result}')
                return None  # Or raise an exception, or handle the "not found" case as appropriate
        except Exception as e:
            print(f"    An error occurred: {e}")
            time.sleep(2)
            # Optionally, handle or re-raise the error depending on your error handling strategy
            return None


    def get_pass_by_id(self, id):
        query = """
        SELECT password
        FROM passwords
        WHERE id = ?
        AND user_id = ?
        """
        try:
            result = pd.read_sql_query(query, con=self.engine, params=(id, self.user_table.user_id,))
            if not result.empty:
                password = result.values[0][0]
                return decrypt_data(self.dek, password)
            else:
                return None  # Or raise an exception, or handle the "not found" case as appropriate
        except Exception as e:
            print(f"An error occurred: {e}")
            # Optionally, handle or re-raise the error depending on your error handling strategy
            return None

    
########################################################
 
def generate_password(length: int = 12, special_chars: str ='#-!£%^&_:'):
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + special_chars
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password
       

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



def setup_new_user(db: SQLManager, username, password)-> bool:
    kek, salt = derive_kek(password)
    edek, dek = encrypt_dek(kek)
    hashed_password = hash_password(password)
    data = UserTable(username=[username], hashed_password=[hashed_password], salt=[salt], edek=[edek])
    return db.register_user(data)



def gen_pass_prompt():
    session = PromptSession()
    bindings = KeyBindings()

    @bindings.add('f2')
    def _(event):
        """Handler for F2 key press to generate password."""
        pwd = generate_password()
        event.app.current_buffer.insert_text(pwd)

    return session.prompt("    Enter to skip password generate or Press F2 to generate password: ", key_bindings=bindings)



def pass_prompt(console: Console, dek)-> PassTable|bool:
    '''
    Add Password data using the TUI prompt
    '''
    console.print('    Website/Name', style='green', end='')
    name: bytes = encrypt_data(dek, Prompt.ask(''))

    console.print('    Username', style='green', end='')
    username: bytes = encrypt_data(dek, Prompt.ask(''))



    password_str =  gen_pass_prompt()

    if password_str == '':    
        console.print('    Password', style='green', end='')
        password_str: str = Prompt.ask('', password=True)
    
        console.print('    Confirm Password', style='green', end='')
        confirm_password: str = Prompt.ask('', password=True)
    
        if password_str != confirm_password:
            print('Passwords do not match, try again')
            return False

    password: bytes = encrypt_data(dek, password_str)
    
    console.print('    Category', style='green', end='')
    category: bytes = encrypt_data(dek, Prompt.ask(''))
    
    console.print('    Notes', style='green', end='')
    notes: bytes = encrypt_data(dek, Prompt.ask(''))

    return PassTable(
        name=[name],
        username=[username],
        password=[password],
        category=[category],
        notes=[notes]
    )

def clear_terminal():
    '''ANSI escape code to clear the screen but keep history'''
    sys.stdout.write('\033[H\033[0J')
    sys.stdout.flush()

from rich.console import Console
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
import string


def pp_prompt(console: Console, prompt_text: str, style: str = '#00CB05', password: bool = False):
    console.print(f'    {prompt_text}: ', style=style, end="")
    if password:
        return getpass.getpass(prompt='')
    else:
        return Prompt.ask('')
    
def auth_register(console: Console, auth: bool = False):
    prompt: str = (
        'Choose Action:\n'
        '\n'
        '    1. Add New User\n'
        '    2. Login\n'
        '    3. Quit\n'
    )
    while auth is False:
        console.print(Panel(prompt,
                            title="Register & Authentication", border_style="bright_blue"), style='aqua')
        action = pp_prompt(console, "Selection", style='green')
        db = SQLManager()
        match action:
            case '1': # Add New User
                username = pp_prompt(console, "Enter your master username")
                password = pp_prompt(console, "Enter your master password", password=True)
                retype_password = pp_prompt(console, "Retype your master password", password=True)
                if password == retype_password:
                    if not pathlib.Path('py_pass.db').exists():
                        db.setup_user_table()

                if setup_new_user(db=db, username=username, password=password):
                    console.print(Panel("User registered successfully"), justify="center", style='yellow')
                else:
                    console.print(Panel("User registration failed"), justify="center", style='red')
        
            case '2': # Login
                username = pp_prompt(console, "Enter your master username")
                password = pp_prompt(console, "Enter your master password", password=True)
                if db.authenticate_user(username=username, password=password):
                    auth = True
                    console.print(Panel(f'User {username} Authenticated Successfully'), justify="center", style='yellow')
        
            case '3' | 'q':
                console.print('    Exiting...\n', style='green')
                exit(0)
            case _:
                console.print('    Unrecognised Option\n', style='red')
                continue
    return db

def get_filtered_items(df: pd.DataFrame, keyword)-> pd.DataFrame:
    keyword = str(keyword).lower()
    mask = df.map(lambda x: keyword in str(x).lower())
    # Use 'any' to filter rows where any column matches the keyword
    return df[mask.any(axis=1)]



def rich_table(df: pd.DataFrame)-> tuple[Table, pd.DataFrame]:
    table = Table(show_header=True, header_style="bold magenta", row_styles=['dim', ''], show_edge=False, highlight=True, padding=(0,1,1,1))
        
    for col in df.columns:
        table.add_column(col.capitalize())
        
    # Add rows to the table
    for _, row in df.iterrows():
        table.add_row(*[str(value) for value in row])
    return table, df
 


def print_paginated_table(console: Console, df: pd.DataFrame, page_size)-> int|str:
    start_row = 0

    while start_row < df.shape[0]:
        table = Table(show_header=True, header_style="bold magenta", row_styles=['dim', ''], show_edge=False, highlight=True, padding=(0,1,1,1))
        
        for col in df.columns:
            table.add_column(col.capitalize())
        
        # Add rows to the table
        for _, row in df.iloc[start_row:start_row + page_size].iterrows():
            table.add_row(*[str(value) for value in row])
        
        console.print(Panel(table, title='Password Table', border_style="bright_blue"), justify='center')
        
        start_row += page_size
        console.print(f"    :e = edit followed by id\n    :d = delete follow by id or list of id's to delete\n    :q = quit\n    :id will copy password to clipboard", style='green')
        response = pp_prompt(console, 'To Change page, Press ENTER to continue', style='green')
        if response:
            return response


def delete_data_entry(console: Console, response: str, db: SQLManager):
    response_list = response.split(' ')
    if 'd' in response_list:
        response_list.remove('d')
    else:
        console.print('    Data Entry Deletion Error', style='error')
    db.delete_data_entry(response_list)
        

def edit_data_entry(console, response, db):
    response_list = response.split(' ')
    if 'e' in response_list:
        response_list.remove('e')
    else:
        console.print('    Data Entry Deletion Error', style='error')
    table, df = db.data_entry_by_id(response_list, console)

    console.print(Panel(table, title='Password Entry', border_style="bright_blue"), justify='center')

    word_dict: dict = {
            df['name'].values[0]: 'name',
            df['username'].values[0]: 'username',
            df['category'].values[0]: 'category',
            df['notes'].values[0]: 'notes'
            }

    fuzzy_completer = FuzzyWordCompleter(sorted([i for i in word_dict.keys()]), meta_dict=word_dict, WORD=True)

    console.print('    Website/Name: ', style='green')
    name: bytes = encrypt_data(db.dek, fuzzy_prompt('    ', completer=fuzzy_completer))

    console.print('    Username:', style='green')
    username: bytes = encrypt_data(db.dek, fuzzy_prompt('    ', completer=fuzzy_completer))

    password_str =  gen_pass_prompt()

    if password_str == '':    
        console.print('    Password', style='green')
        password_str: str = Prompt.ask('    ', password=True)
    
        console.print('    Confirm Password', style='green')
        confirm_password: str = Prompt.ask('    ', password=True)
    
        if password_str != confirm_password:
            print('Passwords do not match, try again')
            return False    
    
    password: bytes = encrypt_data(db.dek, password_str)
    
    console.print('    Category', style='green')
    category: bytes = encrypt_data(db.dek, fuzzy_prompt('    ', completer=fuzzy_completer))
    
    console.print('    Notes', style='green')
    notes: bytes = encrypt_data(db.dek, fuzzy_prompt('    ', completer=fuzzy_completer))

    data = PassTable(
        name=name,
        username=username,
        password=password,
        category=category,
        notes=notes
    )
    db.update_password_for_user(data, df['id'].values[0])

   



def search_db(console:Console, db:SQLManager):
    df: pd.DataFrame = db.get_df()
    decrypted_df: pd.DataFrame = copy(df)
    cols = ['name', 'username', 'category', 'notes']
    words_set: set = set()
    for col in cols:
        # Ensure that the data is in bytes, then decrypt
        decrypted_df[col] = df[col].apply(lambda x: decrypt_data(db.dek, x) if isinstance(x, bytes) else x)
        if col != 'notes':
            temp_set: set = set(decrypted_df[col].to_list())
            words_set.update(temp_set)
    # Get user input for filtering
    fuzzy_completer = FuzzyWordCompleter(sorted(list(words_set)), WORD=True)
    console.print('    Enter a keyword to filter items: ', style='green')
    keyword = fuzzy_prompt(f'    ', completer=fuzzy_completer)

    # Filter items based on input
    filtered_df: pd.DataFrame = get_filtered_items(decrypted_df, keyword)

    response = print_paginated_table(console, filtered_df, 10)
    
    if response == 'q':
        console.print('    q selected, quiting...', style='alert')
        return
    if isinstance(response, str) and response.startswith('d'):
        console.print(f'    d selected, deleting {response}...', style='alert')
        delete_data_entry(console, response, db)
        return
    if isinstance(response, str) and response.startswith('e'):
        console.print(f'    e selected, editing {response}...', style='alert')
        edit_data_entry(console, response, db)
        return
    if response:
        password = db.get_pass_by_id(response)
        if password:
            copy_to_clipboard(console, password, timeout=30)


def parse_file_columns(console: Console, df: pd.DataFrame):
    col_map: dict = {
            'name': ['name', 'website', 'domain', 'url', 'site', 'service'],
            'username': ['login_username', 'username', 'user id', 'account id', 'account', 'login'],
            'password': ['login_password', 'password', 'pass', 'passcode', 'secret', 'pin', 'key'],
            'category': ['category', 'type', 'class', 'group', 'tag'],
            'notes': ['notes', 'details', 'info', 'information', 'description']}

    for col in df.columns:
        col_found = False
        for key, val in col_map.items():
            if col in val:
                df = df.rename(columns={col: key})
                col_found = True
        if col_found is False:
            df = df.drop(columns=col)
            console.print(f'    Column in CSV/JSON File: {col} not available in Database. Ignoring Entry....', style='red')
            time.sleep(1)
        else:
            col_found = False
    return df
    

def file_reader_to_df(console: Console, file: str|pathlib.Path)-> pd.DataFrame|None:
    '''
    file_reader
    -----------

    Args:
        console: Console (for pretty printing)
        file: str (filename for convert to dataframe. Only CSV or JSON file supported)
    Returns:
        pd.DateFrame (With data from csv or json file)
    '''
    file_dict: dict = {
            '.csv': pd.read_csv,
            '.json': pd.read_json
            }
    
    file_suffix = pathlib.Path(file).suffix
    
    reader: pd.DataFrame|None = file_dict.get(file_suffix)
    if reader is None:
        console.print(f'File is invalid, only accept .json or .csv files with the suffix', style='error')
        return
    else:
        return reader(file)


def get_data(console: Console, db: SQLManager):
    inapp: bool = True
    prompt = (
        'Choose Action:\n'
        '\n'
        '    1. Add New Password Entry\n'
        '    2. Search Password\n'
        '    3. See Password Table\n'
        '    4. Upload CSV or JSON File\n'
        '    5. Quit\n'
    )
    while inapp:
        console.print(Panel(prompt,
                            title="Password Management", border_style="bright_blue"), style='aqua')
        action = pp_prompt(console, "Selection", style='green')
        match action:
            case '1':
                data: PassTable = pass_prompt(console, db.dek)
                if data is False:
                    continue
                db.add_password_for_user(data)
            case '2':
                search_db(console, db)
            case '3':
                response = db.load_table(console)
                if response == 'q':
                    continue
                if isinstance(response, str) and response.startswith('d'):
                    delete_data_entry(console, response, db)
                    continue
                if isinstance(response, str) and response.startswith('e'):
                    console.print(f'    e selected, editing {response}...', style='alert')
                    edit_data_entry(console, response, db)
                    continue
                if response:
                    password = db.get_pass_by_id(response)
                    if password:
                        copy_to_clipboard(console, password, timeout=30)
            case '4':
                filename = pathlib.Path(file_system_nav())
                if filename.exists:
                    df = file_reader_to_df(console, filename)
                    if df is not None:
                        df = parse_file_columns(console, df)
                        db.file_to_sql(df)
            case '5' | 'q':
                console.print('    Exiting...\n', style='green')
                inapp = False
            case _:
                console.print(f'    Unrecognised Option: {action}\n', style='red')
                continue


def clear_terminal_and_scroll_data():
    command = 'clear' if os.name == 'posix' else 'cls'
    os.system(command)


def main():
    pypass_theme = Theme({
        "aqua": "#00A6A9", 
        "purple": "#C500B7", 
        "red": "#D10015",
        "error": "#D10015",
        "green": '#00CB05',
        "success": '#00CB05',
        'yellow': '#F2E900',
        'alert': '#ff9933'
    })
    clear_terminal()
    console = Console(theme=pypass_theme)

    if len(sys.argv) > 1:
        db = args_actions(console)
        if db:
            get_data(console, db)
    else:
         # Display a panel with some instructions or information
        console.print(Panel("Welcome to PyPass! Please follow the instructions below.",
                            title="Welcome", border_style="bright_blue"), style='aqua',
                            justify="center")
    
        db: SQLManager = auth_register(console, False)
        get_data(console, db)



def pypass_args():
    # Create the argument parser object
    parser = argparse.ArgumentParser(description="Simple Commandline Password Manager using Pandas and SQLite")
    
    # Define the command line arguments
    parser.add_argument('--add', '-a', nargs='*', help="Add new password entry. Example usage: app.py -a website username password")
    parser.add_argument('--edit', '-e', nargs='*', help="Edit password entry based on username")
    parser.add_argument('--delete', '-d', nargs='*', help="Delete password entry from database")
    parser.add_argument('--table', '-t', action='store_true', help="View Table of password entries, passwords not visible")
    parser.add_argument('--get', '-g', nargs='*', help="Get and decrypt password")
    parser.add_argument('--keygen', '-k', nargs='*', help="Generate keys to encrypt password entries")
    parser.add_argument('--register', '-r', action='store_true', help="Register User Database")
    parser.add_argument('--username', '-u', nargs='*', help="For automation, username can be supplied in the terminal")
    parser.add_argument('--password', '-p', nargs='*', help="For automation, password can be supplied in the terminal")
    parser.add_argument('--config', '-c', nargs='*', help="For automation, yaml or json can be supplied with user credentials")
    parser.add_argument('--interactive', '-i', action='store_true', help="For automation, yaml or json can be supplied with user credentials")

    # Parse the arguments
    args = parser.parse_args()

    # Returning the parsed arguments object
    return args


def keygen_parser(keygen: list):
    num_args = len(keygen)
    args_dict: dict = {}

    try:
        args_dict['length'] = int(keygen[0])
    except ValueError:
        args_dict['special_chars'] = keygen[0]
    
    if num_args == 2:
        try:
            args_dict['length'] = int(keygen[1])
        except ValueError:
            args_dict['special_chars'] = keygen[1]
    
    password = generate_password(**args_dict)

    return password

def args_actions(console):
    args = pypass_args()
    db = SQLManager()
    if args.config:
        with open(pathlib.Path(args.config[0])) as file:
            data = [line.strip() for line in file.readlines()]
            username = data[0]
            password = data[1]
        # Assuming 'args.config' is a list, check if it's not empty
    elif args.username and args.password:
        username = args.username[0]
        password = args.password[0]
    else:
        print("No authentication can take place without a config file or username & password flag")
        exit(0)
    if db.authenticate_user(username,password) is False:
        time.sleep(2)
        exit(0)
    if args.interactive:
        return db
    if args.table:
        db.load_table(console)
    if '-k' in sys.argv or '--keygen' in sys.argv:
        if args.keygen:
            password = keygen_parser(args.keygen)
        else:
            password = generate_password() # default of 12
        print(password, ' Copied to clipboard. Clipboard will not be cleared automatically in non-interactive mode')
        pyclip.copy(password)
        time.sleep(2)
 
if __name__ == '__main__':
    try:
        main()
    finally:
        clear_terminal_and_scroll_data()

