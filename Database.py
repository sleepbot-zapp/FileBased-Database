import os
import json
import shutil
import fcntl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import typing


class ResponseObject:
    """Defines the structure of a parsed response object with dynamic attributes."""
    
    def __init__(self, **data: typing.Dict[str, typing.Any]):
        """
        Initializes the object with dynamic attributes based on the keys in data.
        
        :param data: A dictionary of attributes to set as object properties.
        """
        
        for key, value in data.items():
            setattr(self, key, value)

    def __getitem__(self, key: str):
        """Allows dictionary-style access to the attributes."""
        return getattr(self, key)

    def __repr__(self):
        """Return a string representation of the object excluding the 'data' attribute."""
        
        attributes = {key: value for key, value in self.__dict__.items()}
        return f"{self.__class__.__name__}({', '.join([f'{k}={v!r}' for k, v in attributes.items()])})"


class Database:
    def __init__(self, db_file="database.zdb", key_file="db_key.zkey", iv_file="db_iv.ziv", return_code_message=True):
        """
        Initializes the FileDatabase instance.
        :param db_file: The path to the database file (default: "database.zdb")
        :param key_file: The path to the key file (default: "db_key.zkey")
        :param iv_file: The path to the IV file (default: "db_iv.ziv")
        :param return_code_message: Flag to toggle whether Response Code and Message should be returned (default: True)
        """
        self.db_file = db_file
        self.temp_file = f"{db_file}.temp"
        self.lock_file = f"{db_file}.lock"
        self.key_file = key_file
        self.iv_file = iv_file
        self.data = {}  
        self.staged_data = {}  
        self.return_code_message = return_code_message
        self.key = self._load_or_generate_key(self.key_file, 16)
        self.iv = self._load_or_generate_key(self.iv_file, 16)
        self.load()


    def _load_or_generate_key(self, file_path, length):
        """Loads a key/IV from a file, or generates and saves a new one."""
        if os.path.exists(file_path):
            with open(file_path, "rb") as file:
                return file.read()
        else:
            key = os.urandom(length)
            with open(file_path, "wb") as file:
                file.write(key)
            return key


    def _encrypt(self, plaintext):
        """Encrypts plaintext using AES encryption."""
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()


    def _decrypt(self, ciphertext):
        """Decrypts ciphertext using AES decryption."""
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data.decode()


    def _acquire_lock(self):
        """Creates a lock file to prevent simultaneous writes."""
        if os.path.exists(self.lock_file):
            return self._generate_response(3, "Database is locked by another process.")
        with open(self.lock_file, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)


    def _release_lock(self):
        """Removes the lock file."""
        if os.path.exists(self.lock_file):
            os.remove(self.lock_file)


    def load(self):
        """Loads the database from the file."""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, "rb") as file:
                    encrypted_data = file.read()
                    if encrypted_data:
                        decrypted_data = self._decrypt(encrypted_data)
                        self.data = json.loads(decrypted_data)
                        return self._generate_response(3, "Database integrity check failed.")
                    else:
                        self.data = {}
                return self._generate_response(1, "Database loaded successfully.")
            except Exception as e:
                return self._generate_response(3, f"Error loading database: {str(e)}")
        else:
            return self._generate_response(3, "Database file not found.")



    def commit(self):
        """
        Finalizes staged changes, including deletions, and writes them to the database file.
        """
        try:
            self._acquire_lock()
            for key, value in self.staged_data.items():
                if value is None:  
                    self.data.pop(key, None)
                else:
                    self.data[key] = value
            self.staged_data.clear()  
            with open(self.temp_file, "wb") as temp:
                encrypted_data = self._encrypt(json.dumps(self.data))
                temp.write(encrypted_data)
            shutil.move(self.temp_file, self.db_file)
            return self._generate_response(1, "Changes committed successfully.")
        except Exception as e:
            return self._generate_response(3, f"Error committing changes: {str(e)}")
        finally:
            self._release_lock()


    def add(self, key, value):
        """Adds a key-value pair to the staging area."""
        self.staged_data[key] = value
        return self._generate_response(1, f"Staged: {key} -> {value}", {key: value})


    def update(self, key, value):
        """Updates a key-value pair in the staging area."""
        if key in self.data or key in self.staged_data:
            self.staged_data[key] = value
            return self._generate_response(1, f"Staged update: {key} -> {value}", {key: value})
        else:
            return self._generate_response(2, f"Key '{key}' not found in the database.", None)


    def delete(self, key):
        """
        Stages the deletion of a key-value pair, including the key itself.
        The actual removal occurs only after commit is called.
        """
        if key in self.data or key in self.staged_data:
            self.staged_data[key] = None  
            return self._generate_response(1, f"Staged deletion: {key}")
        else:
            return self._generate_response(2, f"Key '{key}' not found in the database.", None)


    def drop(self):
        """
        Stages the deletion of all keys and their values from the database.
        The actual removal occurs only after commit is called.
        """
        
        self.staged_data.update({key: None for key in self.data.keys()})
        return self._generate_response(1, "Staged deletion of all keys.")



    def search(self, key):
        """
        Retrieves a value by key from the committed database only.
        Staged changes are excluded.
        """
        if key in self.data:
            return self._generate_response(1, "Key found", {key: self.data[key]})
        else:
            return self._generate_response(2, f"Key '{key}' not found.", None)


    def show_all(self):
        """
        Returns all committed key-value pairs from the database.
        Staged changes are excluded.
        """
        return self._generate_response(1, "All committed data retrieved.", self.data)
    

    def show_staged(self):
        """
        Returns all staged key-value pairs that are not yet committed.
        """
        if self.staged_data:
            return self._generate_response(1, "All staged data retrieved.", self.staged_data)
        else:
            return self._generate_response(2, "No staged changes.", None)


    def _generate_response(self, code, message, data=None):
        """Generates the response object, including or excluding the code/message based on the toggle."""
        response_obj = ResponseObject(**(data if isinstance(data, dict) else {}))
        if self.return_code_message:
            return {"Response Code": code, "Response Message": message, "Response": response_obj}
        else:
            return response_obj
