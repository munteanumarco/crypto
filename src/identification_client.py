import socket
import pickle


class IdentificationClient:
    def __init__(self, host='localhost', port=65430):
        self.host = host
        self.port = port

    def register_citizen(self, cnp, first_name, last_name):
        request = {
            "action": "REGISTER",
            "cnp": cnp,
            "first_name": first_name,
            "last_name": last_name
        }
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(pickle.dumps(request))
            response_data = s.recv(4096)

        try:
            response = pickle.loads(response_data)
            return response
        except:
            return {"status": "ERROR", "message": response_data.decode(errors="ignore")}


if __name__ == "__main__":
    client = IdentificationClient()
    cnp = input("Enter CNP: ").strip()
    fname = input("Enter First Name: ").strip()
    lname = input("Enter Last Name: ").strip()

    result = client.register_citizen(cnp, fname, lname)
    print("Server response:", result)
