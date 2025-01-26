import socket
import pickle
from models.candidates import Candidate
from utils.rsa_utils import encrypt

class VotingClient:
    def __init__(self, host='localhost', port=65432, cnp="", pin=""):
        self.host = host
        self.port = port
        self.cnp = cnp
        self.pin = pin
        self.public_key = None

    def get_public_key(self):
        request = {
            "action": "GET_PUBKEY",
            "cnp": self.cnp,
            "pin": self.pin
        }
        response = self._send_request(request)
        if isinstance(response, tuple) and len(response) == 2:
            self.public_key = response
            print("[Client] Public key received:", self.public_key)
        else:
            print("[Client] Could not retrieve public key:", response)

    def cast_vote(self, vote_text):
        if not self.public_key:
            print("[Client] No public key available. Please call get_public_key first.")
            return

        vote_num = int.from_bytes(vote_text.encode(), 'big')
        enc_vote = encrypt(vote_num, self.public_key)

        request = {
            "action": "CAST_VOTE",
            "cnp": self.cnp,
            "pin": self.pin,
            "encrypted_vote": enc_vote
        }
        response = self._send_request(request)
        print("[Client] Server response:", response)

    def _send_request(self, request_dict):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(pickle.dumps(request_dict))
            data = s.recv(4096)

        try:
            return pickle.loads(data)
        except:
            return data.decode(errors='ignore')


if __name__ == "__main__":
    cnp = input("CNP: ")
    pin = input("PIN: ")
    candidates = [
        Candidate("A", "Donald Trump"),
        Candidate("B", "Boris Johnson"),
        Candidate("C", "Angela Merkel")
    ]
    client = VotingClient(cnp=cnp, pin=pin)
    client.get_public_key()

    while client.public_key:
        print("Please choose from the following:")
        for c in candidates:
            print(c)

        vote = input("Enter your vote (A/B/C): ").strip().upper()

        valid_codes = [c.code for c in candidates]
        if vote in valid_codes:
            client.cast_vote(vote)
            print("[Client] Vote cast successfully.")
            break
        else:
            print("[Client] Invalid vote.")
