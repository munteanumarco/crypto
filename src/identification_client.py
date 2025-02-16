import socket
import pickle
from utils.rsa_utils import encrypt, str_to_int


class IdentificationClient:
    def __init__(self, host="localhost", port=65430, server_pub_key=None):
        self.host = host
        self.port = port
        self.server_pub_key = server_pub_key

    def get_public_key(self):
        request = {"action": "GET_PUBKEY"}
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(pickle.dumps(request))
            response_data = s.recv(4096)
        try:
            pub_key = pickle.loads(response_data)
            self.server_pub_key = pub_key
            print("[Client] Public key retrieved:", self.server_pub_key)
            return pub_key
        except Exception as e:
            print("Error retrieving public key:", e)
            return None

    def register_citizen(self, cnp, first_name, last_name):
        if not self.server_pub_key:
            self.get_public_key()
            if not self.server_pub_key:
                raise Exception("Server public key not available.")
        # Encrypt each field using the server's public key.
        encrypted_cnp = encrypt(str_to_int(cnp), self.server_pub_key)
        encrypted_first_name = encrypt(
            str_to_int(first_name), self.server_pub_key
        )
        encrypted_last_name = encrypt(
            str_to_int(last_name), self.server_pub_key
        )

        request = {
            "action": "REGISTER",
            "cnp": encrypted_cnp,
            "first_name": encrypted_first_name,
            "last_name": encrypted_last_name,
        }
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(pickle.dumps(request))
            response_data = s.recv(4096)
        try:
            response = pickle.loads(response_data)
            return response
        except Exception:
            return {
                "status": "ERROR",
                "message": response_data.decode(errors="ignore"),
            }


if __name__ == "__main__":
    client = IdentificationClient()
    cnp = input("Enter CNP: ").strip()
    fname = input("Enter First Name: ").strip()
    lname = input("Enter Last Name: ").strip()

    result = client.register_citizen(cnp, fname, lname)
    print("Server response:", result)
