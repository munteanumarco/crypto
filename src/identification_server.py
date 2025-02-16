import socket
import pickle
from models.db import UsersDb
from utils.rsa_utils import generate_rsa_keys, decrypt, int_to_str


class IdentificationServer:
    def __init__(
        self, host="localhost", port=65430, db_file="voting_db.sqlite"
    ):
        self.host = host
        self.port = port
        self.db = UsersDb(db_file)
        keys = self.db.load_keys()
        if keys is None:
            print("[IDServer] No keys found in DB, generating new RSA keys...")
            pub, priv = generate_rsa_keys(1024)  # use 2048 in production
            self.db.save_keys(pub, priv)
            self.public_key, self.private_key = pub, priv
            print("[IDServer] New keys generated and saved in DB.")
        else:
            self.public_key, self.private_key = keys
            print("[IDServer] Loaded RSA keys from DB.")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"[IDServer] Listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                print(f"[IDServer] Connection from {addr}")
                self.handle_client(conn)
                conn.close()

    def handle_client(self, conn):
        data = conn.recv(4096)
        if not data:
            return

        try:
            request = pickle.loads(data)
        except Exception as e:
            conn.sendall(f"[IDServer] Invalid request: {e}".encode())
            return

        action = request.get("action")
        if action == "GET_PUBKEY":
            # Send the server's public key to the client.
            conn.sendall(pickle.dumps(self.public_key))
        elif action == "REGISTER":
            try:
                # Expect encrypted fields: they are integers encrypted with RSA.
                encrypted_cnp = request.get("cnp")
                encrypted_first_name = request.get("first_name")
                encrypted_last_name = request.get("last_name")

                # Decrypt each field using the private key.
                cnp_int = decrypt(encrypted_cnp, self.private_key)
                first_name_int = decrypt(
                    encrypted_first_name, self.private_key
                )
                last_name_int = decrypt(encrypted_last_name, self.private_key)

                # Convert decrypted integers back to strings.
                cnp = int_to_str(cnp_int)
                first_name = int_to_str(first_name_int)
                last_name = int_to_str(last_name_int)
            except Exception as e:
                conn.sendall(f"[IDServer] Decryption error: {e}".encode())
                return

            if not (cnp and first_name and last_name):
                conn.sendall(
                    b"[IDServer] Missing required fields for registration"
                )
                return

            try:
                # Register the citizen using UsersDb (which handles further hashing).
                pin = self.db.register_citizen(cnp, first_name, last_name)
                response = {"status": "OK", "pin": pin}
                conn.sendall(pickle.dumps(response))
            except ValueError as e:
                response = {"status": "ERROR", "message": str(e)}
                conn.sendall(pickle.dumps(response))
        else:
            conn.sendall(b"[IDServer] Unknown action")


if __name__ == "__main__":
    server = IdentificationServer()
    server.start()
