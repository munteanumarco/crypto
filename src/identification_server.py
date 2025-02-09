import socket
import pickle
from models.db import UsersDb


class IdentificationServer:
    def __init__(
        self, host="localhost", port=65430, db_file="voting_db.sqlite"
    ):
        self.host = host
        self.port = port
        self.db = UsersDb(db_file)

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

        # Attempt to unpickle the request
        try:
            request = pickle.loads(data)
        except Exception as e:
            conn.sendall(f"[IDServer] Invalid request: {e}".encode())
            return

        action = request.get("action")
        if action == "REGISTER":
            # Expecting "cnp", "first_name", "last_name"
            cnp = request.get("cnp")
            first_name = request.get("first_name")
            last_name = request.get("last_name")

            if not (cnp and first_name and last_name):
                conn.sendall(
                    b"[IDServer] Missing required fields for registration"
                )
                return

            try:
                # Register the citizen and generate a PIN
                pin = self.db.register_citizen(cnp, first_name, last_name)
                # Return the PIN to the client
                response = {"status": "OK", "pin": pin}
                conn.sendall(pickle.dumps(response))
            except ValueError as e:
                # If the citizen is already registered or other error
                response = {"status": "ERROR", "message": str(e)}
                conn.sendall(pickle.dumps(response))
        else:
            conn.sendall(b"[IDServer] Unknown action")


if __name__ == "__main__":
    server = IdentificationServer()
    server.start()
