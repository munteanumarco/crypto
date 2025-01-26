import sqlite3
import pickle
import random


class UsersDb:
    def __init__(self, db_file="voting_db.sqlite"):
        self.db_file = db_file
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.init_db()

    def init_db(self):
        cursor = self.conn.cursor()

        # 1) Table: citizens (personal information)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS citizens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cnp TEXT UNIQUE NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL
            )
        """)

        # 2) Table: users (authentication and voting status)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cnp TEXT UNIQUE NOT NULL,
                pin TEXT NOT NULL,
                has_voted INTEGER DEFAULT 0,
                FOREIGN KEY(cnp) REFERENCES citizens(cnp)
            )
        """)

        # 3) Table: votes (encrypted votes)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS votes (
                vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_vote BLOB NOT NULL
            )
        """)

        # 4) Table: keys (RSA keys storage)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                public_key BLOB NOT NULL,
                private_key BLOB NOT NULL
            )
        """)

        # Insert sample citizens if empty
        cursor.execute("SELECT COUNT(*) FROM citizens")
        (citizens_count,) = cursor.fetchone()
        if citizens_count == 0:
            sample_citizens = [
                ("1234567890123", "John",  "Doe"),
                ("9876543210987", "Jane",  "Smith"),
                ("4567890123456", "Alice", "Johnson"),
                ("3210987654321", "Bob",   "Brown"),
                ("1112223334445", "Michael", "Johnson"),
                ("2223334445556", "Sarah", "Williams"),
                ("3334445556667", "David", "Brown"),
                ("4445556667778", "Emily", "Davis"),
                ("5556667778889", "James", "Miller")
            ]
            cursor.executemany("""
                INSERT INTO citizens (cnp, first_name, last_name)
                VALUES (?, ?, ?)
            """, sample_citizens)
            self.conn.commit()
            print("[UsersDb] Sample citizens inserted.")

        # Insert sample users if empty
        cursor.execute("SELECT COUNT(*) FROM users")
        (users_count,) = cursor.fetchone()
        if users_count == 0:
            # Generate PINs for the sample citizens
            sample_users = [
                ("1234567890123", "1234", 0),
                ("9876543210987", "5678", 0),
                ("4567890123456", "9101", 0),
                ("3210987654321", "1121", 0),
            ]
            cursor.executemany("""
                INSERT INTO users (cnp, pin, has_voted)
                VALUES (?, ?, ?)
            """, sample_users)
            self.conn.commit()
            print("[UsersDb] Sample users inserted.")

        self.conn.commit()

    def register_citizen(self, cnp, first_name, last_name):
        """
        Registers a new citizen by adding entries to 'users' tables.
        Generates a random 4-digit PIN for the user.
        Raises ValueError if the CNP already exists.
        """
        cursor = self.conn.cursor()

        # Check if CNP already exists in users
        cursor.execute("SELECT id FROM users WHERE cnp = ?", (cnp,))
        if cursor.fetchone():
            raise ValueError(f"[UsersDb] CNP {cnp} is already registered.")

        # Generate a random 4-digit PIN
        pin = "".join(str(random.randint(0, 9)) for _ in range(4))

        # Insert into users table
        cursor.execute("""
            INSERT INTO users (cnp, pin, has_voted)
            VALUES (?, ?, 0)
        """, (cnp, pin))

        self.conn.commit()
        print(f"[UsersDb] Citizen registered: CNP={cnp}, PIN={pin}")
        return pin

    def authenticate_user(self, cnp, pin):
        """
        Authenticates a user based on CNP and PIN.
        Returns a tuple (id, cnp, has_voted) if successful, else None.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, cnp, has_voted
            FROM users
            WHERE cnp = ? AND pin = ?
        """, (cnp, pin))
        row = cursor.fetchone()
        return row  # Example: (id, cnp, has_voted) or None

    def mark_user_has_voted(self, user_id):
        """
        Marks the user as having voted by setting has_voted to 1.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE users
               SET has_voted = 1
             WHERE id = ?
        """, (user_id,))
        self.conn.commit()
        print(f"[UsersDb] User with ID={user_id} has voted.")

    def store_encrypted_vote(self, ciphertext):
        """
        Stores the encrypted vote in the votes table as a BLOB.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO votes (encrypted_vote)
            VALUES (?)
        """, (ciphertext,))
        self.conn.commit()
        print("[UsersDb] Encrypted vote stored.")
        return cursor.lastrowid

    # ---------------------------
    # KEY STORAGE / RETRIEVAL
    # ---------------------------

    def save_keys(self, public_key, private_key):
        """
        Stores the RSA public and private keys in the 'keys' table.
        If keys already exist, they are updated.
        """
        cursor = self.conn.cursor()
        pickled_pub = pickle.dumps(public_key)
        pickled_priv = pickle.dumps(private_key)

        cursor.execute("SELECT COUNT(*) FROM keys")
        (count,) = cursor.fetchone()
        if count == 0:
            cursor.execute("""
                INSERT INTO keys (id, public_key, private_key)
                VALUES (1, ?, ?)
            """, (pickled_pub, pickled_priv))
            print("[UsersDb] RSA keys stored in DB.")
        else:
            cursor.execute("""
                UPDATE keys
                   SET public_key = ?, private_key = ?
                 WHERE id = 1
            """, (pickled_pub, pickled_priv))
            print("[UsersDb] RSA keys updated in DB.")
        self.conn.commit()

    def load_keys(self):
        """
        Loads the RSA public and private keys from the 'keys' table.
        Returns a tuple (public_key, private_key) if found, else None.
        """
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

    def close(self):
        """
        Closes the database connection.
        """
        self.conn.close()
        print("[UsersDb] Database connection closed.")
