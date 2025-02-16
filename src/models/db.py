import sqlite3
import pickle
import random
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib


# Deterministic hash function for non-secret fields that require lookup.
def deterministic_hash(s, salt="fixed_salt_value"):
    return hashlib.sha256((salt + s).encode()).hexdigest()


class UsersDb:
    def __init__(self, db_file="voting_db.sqlite"):
        self.db_file = db_file
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.init_db()

    def init_db(self):
        cursor = self.conn.cursor()

        # 1) Table: citizens (personal information) – all fields are hashed deterministically.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS citizens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cnp TEXT UNIQUE NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL
            )
            """
        )

        # 2) Table: users (authentication and voting status)
        # Note: The cnp here is stored as the deterministic hash (to match the citizens table)
        # and the PIN is stored as a salted hash using generate_password_hash.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cnp TEXT UNIQUE NOT NULL,
                pin TEXT NOT NULL,
                has_voted INTEGER DEFAULT 0,
                FOREIGN KEY(cnp) REFERENCES citizens(cnp)
            )
            """
        )

        # 3) Table: votes (encrypted votes)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS votes (
                vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_vote BLOB NOT NULL
            )
            """
        )

        # 4) Table: keys (RSA keys storage)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                public_key BLOB NOT NULL,
                private_key BLOB NOT NULL
            )
            """
        )

        # 5) Table: admins (admin credentials storage)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
            """
        )

        # Insert sample citizens if empty – hash each field deterministically.
        cursor.execute("SELECT COUNT(*) FROM citizens")
        (citizens_count,) = cursor.fetchone()
        if citizens_count == 0:
            sample_citizens = [
                ("1234567890123", "John", "Doe"),
                ("9876543210987", "Jane", "Smith"),
                ("4567890123456", "Alice", "Johnson"),
                ("3210987654321", "Bob", "Brown"),
                ("1112223334445", "Michael", "Johnson"),
                ("2223334445556", "Sarah", "Williams"),
                ("3334445556667", "David", "Brown"),
                ("4445556667778", "Emily", "Davis"),
                ("5556667778889", "James", "Miller"),
            ]
            # Hash each value deterministically
            hashed_citizens = [
                (
                    deterministic_hash(cnp),
                    deterministic_hash(first_name),
                    deterministic_hash(last_name),
                )
                for cnp, first_name, last_name in sample_citizens
            ]
            cursor.executemany(
                """
                INSERT INTO citizens (cnp, first_name, last_name)
                VALUES (?, ?, ?)
                """,
                hashed_citizens,
            )
            self.conn.commit()
            print("[UsersDb] Sample citizens inserted.")

        # Insert sample users if empty – hash the CNP deterministically and the PIN using generate_password_hash.
        cursor.execute("SELECT COUNT(*) FROM users")
        (users_count,) = cursor.fetchone()
        if users_count == 0:
            sample_users = [
                ("1234567890123", "1234", 0),
                ("9876543210987", "5678", 0),
                ("4567890123456", "9101", 0),
                ("3210987654321", "1121", 0),
            ]
            hashed_users = []
            for cnp, pin, voted in sample_users:
                hashed_cnp = deterministic_hash(cnp)
                hashed_pin = generate_password_hash(pin)
                hashed_users.append((hashed_cnp, hashed_pin, voted))
            cursor.executemany(
                """
                INSERT INTO users (cnp, pin, has_voted)
                VALUES (?, ?, ?)
                """,
                hashed_users,
            )
            self.conn.commit()
            print("[UsersDb] Sample users inserted.")

        # Insert default admin if none exists (admin password is hashed via generate_password_hash)
        cursor.execute("SELECT COUNT(*) FROM admins")
        (admin_count,) = cursor.fetchone()
        if admin_count == 0:
            default_username = "admin"
            default_password = "secret"
            hashed_password = generate_password_hash(default_password)
            cursor.execute(
                """
                INSERT INTO admins (username, password)
                VALUES (?, ?)
                """,
                (default_username, hashed_password),
            )
            self.conn.commit()
            print("[UsersDb] Default admin inserted.")

        self.conn.commit()

    def register_citizen(self, cnp, first_name, last_name):
        cursor = self.conn.cursor()
        # Check if this citizen is already registered based on the deterministic hash of the CNP.
        hashed_cnp = deterministic_hash(cnp)
        cursor.execute("SELECT id FROM users WHERE cnp = ?", (hashed_cnp,))
        if cursor.fetchone():
            raise ValueError(f"[UsersDb] CNP {cnp} is already registered.")

        # Generate a random 4-digit PIN, hash it using generate_password_hash for secure storage,
        # and insert into users table (using the hashed CNP)
        pin = "".join(str(random.randint(0, 9)) for _ in range(4))
        hashed_pin = generate_password_hash(pin)
        cursor.execute(
            """
            INSERT INTO users (cnp, pin, has_voted)
            VALUES (?, ?, 0)
            """,
            (hashed_cnp, hashed_pin),
        )
        self.conn.commit()
        print(f"[UsersDb] Citizen registered: CNP={cnp}, PIN={pin}")
        return pin

    def authenticate_user(self, cnp, pin):
        cursor = self.conn.cursor()
        hashed_cnp = deterministic_hash(cnp)
        cursor.execute(
            """
            SELECT id, cnp, has_voted, pin
            FROM users
            WHERE cnp = ?
            """,
            (hashed_cnp,),
        )
        row = cursor.fetchone()
        # row[3] is the stored hashed PIN
        if row and check_password_hash(row[3], pin):
            return row[:3]  # Return id, cnp, has_voted
        return None

    def mark_user_has_voted(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            UPDATE users
               SET has_voted = 1
             WHERE id = ?
            """,
            (user_id,),
        )
        self.conn.commit()
        print(f"[UsersDb] User with ID={user_id} has voted.")

    def store_encrypted_vote(self, ciphertext):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO votes (encrypted_vote)
            VALUES (?)
            """,
            (ciphertext,),
        )
        self.conn.commit()
        print("[UsersDb] Encrypted vote stored.")
        return cursor.lastrowid

    def save_keys(self, public_key, private_key):
        cursor = self.conn.cursor()
        pickled_pub = pickle.dumps(public_key)
        pickled_priv = pickle.dumps(private_key)
        cursor.execute("SELECT COUNT(*) FROM keys")
        (count,) = cursor.fetchone()
        if count == 0:
            cursor.execute(
                """
                INSERT INTO keys (id, public_key, private_key)
                VALUES (1, ?, ?)
                """,
                (pickled_pub, pickled_priv),
            )
            print("[UsersDb] RSA keys stored in DB.")
        else:
            cursor.execute(
                """
                UPDATE keys
                   SET public_key = ?, private_key = ?
                 WHERE id = 1
                """,
                (pickled_pub, pickled_priv),
            )
            print("[UsersDb] RSA keys updated in DB.")
        self.conn.commit()

    def load_keys(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT public_key, private_key FROM keys WHERE id = 1")
        row = cursor.fetchone()
        if row:
            pickled_pub, pickled_priv = row
            public_key = pickle.loads(pickled_pub)
            private_key = pickle.loads(pickled_priv)
            print("[UsersDb] RSA keys loaded from DB.")
            return public_key, private_key
        print("[UsersDb] No RSA keys found in DB.")
        return None

    def get_admin(self, username):
        """
        Retrieves the admin record for the given username.
        Returns a tuple (id, username, password) if found, else None.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id, username, password FROM admins WHERE username = ?
            """,
            (username,),
        )
        return cursor.fetchone()

    def close(self):
        self.conn.close()
        print("[UsersDb] Database connection closed.")
