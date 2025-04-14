#!/usr/bin/env python3

import polars as pl, sqlite3
import hashlib, binascii, os, pathlib, datetime, argparse, base64, getpass, sys, pyclip, threading, time, secrets, string
from threading import Timer
from queue import Queue
from dataclasses import dataclass, field, asdict
from functools import wraps
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.theme import Theme
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
import string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from prompt_toolkit.completion import FuzzyWordCompleter
from prompt_toolkit import prompt as fuzzy_prompt
from copy import copy
from pypass.navigation import file_system_nav
from pathlib import Path

#################### Clipboard #########################

def user_interaction(console: Console, q: Queue):
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



def get_default_db_path():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', help='Path to the password database')
    args, unknown = parser.parse_known_args()

    if args.db:
        # Resolve to absolute path relative to current working directory
        return str(Path(args.db).resolve())
    
    # Fallback: user home dir
    home = Path.home()
    fallback = home / ".pypass" / "py_pass.db"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    return str(fallback)

class SQLManager:
    def __init__(self):
        db_path = get_default_db_path()
        self.conn = sqlite3.connect(db_path)
        self.user_table: UserTable = None
        self.dek = None
        self.setup_user_table()

    def setup_user_table(self):
        # Create the 'users' table
        self.conn.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                        user_id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        hashed_password TEXT NOT NULL,
                        salt BLOB NOT NULL,
                        edek BLOB NOT NULL
                        );
                        """)

            # Create the 'passwords' table
        self.conn.execute("""
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
                            """)

        self.conn.commit()
            
    def register_user(self, data: UserTable):
        """Register a new user with a hashed password."""
        data_dict = asdict(data)
        keys = ', '.join(data_dict.keys())
        question_marks = ', '.join(['?' for _ in data_dict])
        values = tuple(data_dict.values())

        query = f"INSERT INTO users ({keys}) VALUES ({question_marks})"
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, values)
            self.conn.commit()
            return True
        except Exception as e:
            return False
    
    def enter_pass_data(self, data: PassTable):
        """Register a new user with a hashed password."""
        data_dict = asdict(data)
        keys = ', '.join(data_dict.keys())
        question_marks = ', '.join(['?' for _ in data_dict])
        values = tuple(data_dict.values())

        query = f"INSERT INTO passwords ({keys}) VALUES ({question_marks})"
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, values)
            self.conn.commit()
            return True
        except Exception as e:
            return False
        
    def get_query(self, query, params):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        # Assume we know the column names and types, adjust as necessary
        return rows, cursor.description
    
    def get_df_query_params(self, query, params)-> pl.DataFrame:
        rows, description = self.get_query(query, params)
        # Assume we know the column names and types, adjust as necessary
        columns = [description[0] for description in description]
        df = pl.DataFrame(rows, orient='row', schema=columns)
        return df
    
    def authenticate_user(self, username, password):
        """Authenticate a user by their username and password."""
        try:
            # Query user data from SQLite database
            query = "SELECT user_id, username, hashed_password, salt, edek FROM users WHERE username = ?"
            result: pl.DataFrame = self.get_df_query_params(query, (username,))
            if result.height > 0:
                if verify_password(result['hashed_password'][0], password):
                    self.user_table = UserTable(
                        username=result['username'][0],
                        hashed_password=result['hashed_password'][0],
                        salt=result['salt'][0],
                        edek=result['edek'][0],
                    )
                    self.user_table.add_user_id(user_id=result['user_id'][0])
                    kek, _ = derive_kek(password, self.user_table.salt)
                    self.dek = decrypt_dek(kek, self.user_table.edek)
                    return True
            print('Authentication failed')
            return False
        except Exception as e:
            print(f'Auth failed {e}')
            return False

        
    def add_password_for_user(self, data: PassTable):
        data.add_user_id(self.user_table.user_id)
        self.enter_pass_data(data)
        print("    Password added successfully.")
        return

    def update_password_for_user(self, data: PassTable, id: int):
        query = '''
        UPDATE passwords 
        SET name = :name, username = :username, password = :password, category = :category, notes = :notes
        WHERE id = :id AND user_id = :user_id
        '''
        data.add_user_id(self.user_table.user_id[0])
        data.add_id(id)
        with self.conn as conn:
            conn.execute(query, asdict(data))
            conn.commit()
            print("    Password updated successfully.")
        return

    def sort_val(self,df: pl.DataFrame):
        # Create a temporary column for case-insensitive sorting
        df = df.with_columns(df['name'].str.to_lowercase().alias('name_lower'))
        df = df.sort('name_lower')
        df = df.drop('name_lower')
        return df

    def file_to_sql(self, df: pl.DataFrame):
        cursor = self.conn.cursor()

        # Assume df is a Polars DataFrame that needs to be converted to a list of dictionaries for insertion
        records = df.to_pandas().to_dict('records')  # Convert to Pandas DataFrame then to list of dicts

        # Encrypt data in specified columns
        cols = ['name', 'username', 'password', 'category', 'notes']
        for record in records:
            for col in cols:
                record[col] = encrypt_data(self.dek, str(record[col]))

        # SQL Insert Statement
        columns = ', '.join(cols + ['user_id'])
        placeholders = ', '.join(['?' for _ in cols] + ['?'])
        sql = f"INSERT INTO passwords ({columns}) VALUES ({placeholders})"

        try:
            # Insert each record into the database
            for record in records:
                values = [record[col] for col in cols] + [self.user_table.user_id]
                cursor.execute(sql, values)
            self.conn.commit()
            print('    File Uploaded into Database Successfully')
        except Exception as e:
            print(f'    File upload failed: {e}')
            self.conn.rollback()  # Roll back in case of error


    def get_df(self)-> pl.DataFrame:
        query = "SELECT * FROM passwords WHERE user_id = ?"
        df = self.get_df_query_params(query, (self.user_table.user_id,))
        return df

        
    def decrypt_table(self, cols: list = ['name', 'username', 'category', 'notes']):
        df: pl.DataFrame = self.get_df()

        for col in cols:
            df = df.with_columns(
                    df[col].map_elements(
                        lambda x: decrypt_data(self.dek, x) if isinstance(x, bytes) else x,
                        return_dtype=pl.Utf8
                    ).alias(col)
                )
        return df

    def load_table(self, console):
        """Load and display passwords related to a specific user from the SQLite database."""
        decrypted_df = self.decrypt_table()
        return print_paginated_table(console, decrypted_df, 10)

    def name_user_list(self):
        name_user_list = ['name', 'username']
        df: pl.DataFrame = self.decrypt_table(name_user_list)

        df = self.sort_val(df)
        df = df[name_user_list]

        str_builder = ''
        for data in df.rows():
            str_builder += f'{data[0]},{data[1]}\n'
        return str_builder

    def get_pass(self, name, username):
        try:
            name_user_list = ['name', 'username', 'password']
            df: pl.DataFrame = self.decrypt_table(name_user_list)
            df = self.sort_val(df)
            # Perform the filter and retrieve the password
            result = df.filter((df["name"] == name) & (df["username"] == username))["password"]
            if result.len() > 0:
                return result[0]
            else:
                return None  # or handle as needed if no results are found
        except Exception as e:
            print(f"    An error occurred: {e}")
            # Optionally, handle or re-raise the error depending on your error handling strategy
            return None


    def delete_data_entry(self, entry: list):
        query = "DELETE FROM passwords WHERE id = ? AND user_id = ?"
        try:
            cursor = self.conn.cursor()
            for id in entry:
                # Prepare parameters
                params = (id, self.user_table.user_id)  # Accessing the first user_id if it's stored in a list
                cursor.execute(query, params)
            self.conn.commit()
        except Exception as e:
            print(f"    An error occurred: {e}")  # Debugging output


    def data_entry_by_id(self, id: int, console: Console):
        query = """
        SELECT *
        FROM passwords
        WHERE id = ?
        AND user_id = ?
        """
        # Execute the query using the first id provided and the user's id
        try:
            result: pl.DataFrame = self.get_df_query_params(query, (id, self.user_table.user_id))
            if not result.is_empty():
                # Decrypt data only for the specific byte columns if needed
                decrypted_columns = []
                for col in result.columns:
                    if result[col].dtype == pl.Utf8:
                        decrypted_columns.append(result[col].apply(lambda x: decrypt_data(self.dek, x) if isinstance(x, bytes) else x).alias(col))
                    else:
                        decrypted_columns.append(result[col])

                decrypted_data = result.with_columns(decrypted_columns)

                # Create a Rich Table to display the data
                return rich_table(decrypted_data, console)
            else:
                print(f'    No result found with database query, id: {id}')
                return None
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
            result: pl.DataFrame = self.get_df_query_params(query, (id, self.user_table.user_id))
            if not result.is_empty():
                password = result["password"][0]
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
    data = UserTable(username=username, hashed_password=hashed_password, salt=salt, edek=edek)
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
        name=name,
        username=username,
        password=password,
        category=category,
        notes=notes
    )

def clear_terminal():
    '''ANSI escape code to clear the screen but keep history'''
    sys.stdout.write('\033[H\033[0J')
    sys.stdout.flush()


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
                    if not pathlib.Path('py_pass_polars.db').exists():
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



def get_filtered_items(df: pl.DataFrame, keyword) -> pl.DataFrame:
    keyword = str(keyword).lower()
    
    # Create a mask for each column and combine them with logical OR
    mask = None
    for column in df.columns:
        # Only apply to string type columns
        if df[column].dtype == pl.Utf8:
            # Convert column to lowercase and check if it contains the lowercase keyword
            col_mask = df[column].str.to_lowercase().str.contains(keyword)
            mask = col_mask if mask is None else (mask | col_mask)
    
    # Filter the DataFrame based on the combined mask
    return df.filter(mask)


def rich_table(df: pl.DataFrame)-> tuple[Table, pl.DataFrame]:
    table = Table(show_header=True, header_style="bold magenta", row_styles=['dim', ''], show_edge=False, highlight=True, padding=(0,1,1,1))
        
    for col in df.columns:
        table.add_column(col.capitalize())
        
    # Add rows to the table
    for row in df.rows():
        table.add_row(*[str(value) for value in row])
    return table, df
 


def print_paginated_table(console: Console, df: pl.DataFrame, page_size)-> int|str:
    start_row = 0
    total_rows = df.height

    while start_row < total_rows:
        table = Table(show_header=True, header_style="bold magenta", row_styles=['dim', ''], show_edge=False, highlight=True, padding=(0,1,1,1))
        
        for col in df.columns:
            table.add_column(col.capitalize())

        # Add rows to the table using slicing
        end_row = min(start_row + page_size, total_rows)
        sliced_df = df.slice(start_row, end_row - start_row)

        # Append rows to the table
        for row in sliced_df.rows():  # Directly using polars to iterate over rows
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
        

def edit_data_entry(console: Console, response: str, db: SQLManager):
    response_list = response.split(' ')
    if 'e' in response_list:
        response_list.remove('e')
    else:
        console.print('    Data Entry Deletion Error', style='error')
    table, df = db.data_entry_by_id(response_list, console)

    console.print(Panel(table, title='Password Entry', border_style="bright_blue"), justify='center')
    df: pl.DataFrame
    word_dict: dict = {
            df['name'][0]: 'name',
            df['username'][0]: 'username',
            df['category'][0]: 'category',
            df['notes'][0]: 'notes'
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
            print('    Passwords do not match, try again')
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
    db.update_password_for_user(data, df['id'])


def search_db(console:Console, db:SQLManager):
    df: pl.DataFrame = db.get_df()
    decrypted_df: pl.DataFrame = df.clone()
    cols = ['name', 'username', 'category', 'notes']
    words_set: set = set()

    # Apply decryption and create a new DataFrame
    # Assuming df[col] contains encrypted data in bytes that needs to be decrypted
    for col in cols:
        decrypted_df = decrypted_df.with_columns(
                decrypted_df[col].map_elements(
                    lambda x: decrypt_data(db.dek, x) if isinstance(x, bytes) else x,
                    return_dtype=pl.Utf8  # or the appropriate data type expected from decrypt_data
                ).alias(col)
            )

    # Collect words for completer excluding 'notes'
    words_set = set()
    for col in cols:  # Excluding 'notes'
        words_set.update(decrypted_df[col].to_list())

    # Get user input for filtering
    fuzzy_completer = FuzzyWordCompleter(sorted(list(words_set)), WORD=True)
    console.print('    Enter a keyword to filter items: ', style='green')
    keyword = fuzzy_prompt(f'    ', completer=fuzzy_completer)

    # Filter items based on input
    filtered_df: pl.DataFrame = get_filtered_items(decrypted_df, keyword)

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


def parse_file_columns(console: Console, df: pl.DataFrame):
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
                df = df.rename({col: key})
                col_found = True
        if col_found is False:
            df = df.drop(columns=col)
            console.print(f'    Column in CSV/JSON File: {col} not available in Database. Ignoring Entry....', style='red')
            time.sleep(1)
        else:
            col_found = False
    return df
    

def file_reader_to_df(console: Console, file: str|pathlib.Path)-> pl.DataFrame|None:
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
            '.csv': pl.read_csv,
            '.json': pl.read_json
            }
    
    file_suffix = pathlib.Path(file).suffix
    
    reader: pl.DataFrame|None = file_dict.get(file_suffix)
    if reader is None:
        console.print(f'    File is invalid, only accept .json or .csv files with the suffix', style='error')
        return
    else:
        return reader(file)

def load_table_parser(db: SQLManager, console: Console):
    response = db.load_table(console)
    if isinstance(response, str) and response.startswith('d'):
        delete_data_entry(console, response, db)
    if isinstance(response, str) and response.startswith('e'):
        console.print(f'    e selected, editing {response}...', style='alert')
        edit_data_entry(console, response, db)
    if response:
        password = db.get_pass_by_id(response)
        if password:
            return password
    else:
        return None


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
                clear_terminal_and_scroll_data()
            case _:
                console.print(f'    Unrecognised Option: {action}\n', style='red')
                continue


def clear_terminal_and_scroll_data():
    command = 'clear' if os.name == 'posix' else 'cls'
    os.system(command)
    exit(0)


def interactive_mode(console: Console):
    # Display a panel with some instructions or information
    console.print(Panel("Welcome to PyPass! Please follow the instructions below.",
                        title="Welcome", border_style="bright_blue"), style='aqua',
                        justify="center")
            
    db: SQLManager = auth_register(console, False)
    get_data(console, db)
    return db


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
    try:
        if len(sys.argv) > 1:
            db = args_actions(console)
            if db:
                get_data(console, db)
        else:
            db = interactive_mode(console)
    finally:
        try:
            db.conn.close()
        except (UnboundLocalError, AttributeError):
            pass # db not initialised, so no closing required


def pypass_args():
    # Create the argument parser object
    parser = argparse.ArgumentParser(description="Simple Commandline Password Manager using Pandas and SQLite")
    
    # Define the command line arguments
    parser.add_argument('--add', '-a', nargs='*', help="Add new password entry. Example usage: app.py -a website username password") # Not supported
    # parser.add_argument('--edit', '-e', nargs='*', help="Edit password entry based on username") # Not supported
    # parser.add_argument('--delete', '-d', nargs='*', help="Delete password entry from database") # Not supported
    parser.add_argument('--table', '-t', action='store_true', help="View Table of password entries, passwords not visible")
    parser.add_argument('--get', '-g', nargs='*', help="Get and decrypt password, comma separated. i.e. 'Twitter,username'. Note: No space after the comma")
    parser.add_argument('--keygen', '-k', nargs='*', help="Generate keys. Default is 12 chars '#-!£%%^&_:'. Args should look like this --keygen 15 '!£$%%$^', which represents password length and special chars")
    # parser.add_argument('--register', '-r', action='store_true', help="Register User Database") # Not supported
    parser.add_argument('--username', '-u', nargs='*', help="For automation, username can be supplied in the terminal")
    parser.add_argument('--password', '-p', nargs='*', help="For automation, password can be supplied in the terminal")
    parser.add_argument('--config', '-c', nargs='*', help="For automation, text file can be supplied with user credentials")
    parser.add_argument('--interactive', '-i', action='store_true', help="You can supply config file to log in automatically and get to the dashboard")
    parser.add_argument('--ls', '-l', action='store_true', help="List of website/names and usernames")
    parser.add_argument('--db', nargs=1, help="Path to database file")

    # Parse the arguments
    args = parser.parse_args()

    # Returning the parsed arguments object
    return args


def keygen_parser(keygen: list):
    args_dict: dict = {}
    found_length = False
    
    for arg in keygen:
        try:
            # Attempt to convert each argument to an integer
            value = int(arg)
            args_dict['length'] = value
            found_length = True
        except ValueError:
            # If it's not an integer, treat it as special characters
            # This ensures we don't overwrite the entry if already set
            if 'special_chars' not in args_dict:
                args_dict['special_chars'] = arg
    
    # If no valid length was found, set a default or raise an error
    if not found_length:
        raise ValueError(f"Unable to parse args passed to kegen. Args should be something like this 15 '!£$%$^', which represents password length and special chars")
    
    password = generate_password(**args_dict)

    return password

def args_actions(console):
    args = pypass_args()
    db = SQLManager()

    if '-k' in sys.argv or '--keygen' in sys.argv:
        if args.keygen:
            password = keygen_parser(args.keygen)
        else:
            password = generate_password() # default of 12
        print(password, ' Copied to clipboard. Clipboard will not be cleared automatically in non-interactive mode')
        pyclip.copy(password)

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
        print("No authentication can take place without a config file or username & password flag, entering interactive mode")
        db = interactive_mode(console)
        return db
    if db.authenticate_user(username,password) is False:
        exit(0)
    if args.interactive:
        return db
    if args.table:
        password = load_table_parser(db, console)
        if password:
            pyclip.copy(password)
        clear_terminal_and_scroll_data()
    if args.ls:
        print(db.name_user_list())
    if args.get:
        data = args.get[0].split(',')
        password = db.get_pass(*data)
        pyclip.copy(password)
        print(password)

 
if __name__ == '__main__':
    main()

