import socket
import pickle
from models.db import UsersDb
from utils.rsa_utils import generate_rsa_keys


class VotingServer:
    def __init__(
        self, host="localhost", port=65432, db_file="voting_db.sqlite"
    ):
        self.host = host
        self.port = port
        self.db = UsersDb(db_file)

        # 1) Try to load keys from DB
        keys = self.db.load_keys()
        if keys is None:
            # 2) If no keys in DB, generate & store them
            print("[Server] No keys found in DB, generating new RSA keys...")
            pub, priv = generate_rsa_keys(1024)  # or 2048
            self.db.save_keys(pub, priv)
            self.public_key, self.private_key = pub, priv
            print("[Server] New keys generated and saved in DB.")
        else:
            # 3) If found, just use them
            self.public_key, self.private_key = keys
            print("[Server] Loaded RSA keys from DB.")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"[Server] Listening on {self.host}:{self.port}")

            while True:
                conn, addr = s.accept()
                print(f"[Server] Connection from {addr}")
                self.handle_client(conn)
                conn.close()

    def handle_client(self, conn):
        data = conn.recv(4096)
        if not data:
            return

        try:
            request = pickle.loads(data)
        except Exception as e:
            conn.sendall(f"[Server] Invalid request: {e}".encode())
            return

        action = request.get("action")
        cnp = request.get("cnp")
        pin = request.get("pin")

        # Verify user
        user_row = self.db.authenticate_user(cnp, pin)
        if not user_row:
            conn.sendall(b"[Server] ERROR: Invalid CNP or PIN")
            return

        user_id, user_cnp, has_voted = user_row

        if action == "GET_PUBKEY":
            conn.sendall(pickle.dumps(self.public_key))

        elif action == "CAST_VOTE":
            if has_voted == 1:
                conn.sendall(b"[Server] ERROR: You have already voted.")
                return

            encrypted_vote_int = request.get("encrypted_vote")
            if encrypted_vote_int is None:
                conn.sendall(b"[Server] ERROR: No vote provided")
                return

            # Convert int → bytes for DB storage
            try:
                ciphertext_bytes = encrypted_vote_int.to_bytes(
                    (encrypted_vote_int.bit_length() + 7) // 8, "big"
                )
                self.db.store_encrypted_vote(ciphertext_bytes)
                self.db.mark_user_has_voted(user_id)

                conn.sendall(b"[Server] VOTE_ACCEPTED (encrypted vote stored)")
                print(f"[Server] Stored vote for user cnp={user_cnp}")
            except Exception as e:
                conn.sendall(f"[Server] ERROR storing vote: {e}".encode())

        else:
            conn.sendall(b"[Server] ERROR: Unknown action")


if __name__ == "__main__":
    server = VotingServer()
    server.start()
# sdadsadsa da sd as
