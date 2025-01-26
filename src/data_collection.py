import sqlite3
import pickle


class DataCollection:
    def __init__(self, db_file="voting_db.sqlite"):
        self.db_file = db_file
        # We load the RSA private key from the 'keys' table
        self.private_key = None
        self._connect_and_load_key()

    def _connect_and_load_key(self):
        """
        Connect to the DB and load the private key from the 'keys' table at row id=1.
        """
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        cursor = self.conn.cursor()

        # keys table must have (public_key, private_key) as pickled BLOBs
        cursor.execute("SELECT private_key FROM keys WHERE id = 1")
        row = cursor.fetchone()
        if not row:
            raise ValueError(
                "[DataCollection] No keys found in DB. Cannot decrypt votes.")

        pickled_priv = row[0]
        self.private_key = pickle.loads(pickled_priv)
        # self.private_key should now be (d, n)

    def decrypt_vote(self, ciphertext_blob):
        """
        Convert the BLOB -> int -> decrypt -> retrieve the plaintext string.
        """
        # Convert bytes to an integer
        ciphertext_int = int.from_bytes(ciphertext_blob, 'big')

        # RSA decryption: m = c^d mod n
        d, n = self.private_key
        decrypted_int = pow(ciphertext_int, d, n)

        # Convert decrypted int back to bytes
        vote_bytes = decrypted_int.to_bytes(
            (decrypted_int.bit_length() + 7) // 8, 'big')

        # Decode to get the original vote string (e.g. "A")
        return vote_bytes.decode(errors='ignore')

    def collect_votes(self):
        """
        Fetch all encrypted votes from 'votes' table, decrypt them, and return a list of strings.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT encrypted_vote FROM votes")
        rows = cursor.fetchall()

        decrypted_votes = []
        for (enc_blob,) in rows:
            vote_str = self.decrypt_vote(enc_blob)
            decrypted_votes.append(vote_str)
        return decrypted_votes

    def get_statistics(self):
        """
        Decrypt all votes, tally them, and return a dictionary of counts, e.g.: {'A': 5, 'B': 2, ...}.
        """
        all_votes = self.collect_votes()
        stats = {}
        for v in all_votes:
            stats[v] = stats.get(v, 0) + 1
        return stats

    def close(self):
        self.conn.close()


if __name__ == "__main__":
    data_collector = DataCollection("voting_db.sqlite")
    stats = data_collector.get_statistics()
    data_collector.close()

    print("[DataCollection] Stats:", stats)

    total = sum(stats.values())
    if total == 0:
        print("No votes.")
    else:
        for key, val in stats.items():
            pct = (val / total) * 100
            print(f"{key}: {val} votes ({pct:.1f}%)")
