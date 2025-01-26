class User:
    def __init__(self, cnp, first_name, last_name, pin):
        self._cnp = cnp
        self._first_name = first_name
        self._last_name = last_name
        self._pin = pin

    def get_cnp(self):
        return self._cnp

    def verify_pin(self, pin):
        return self._pin == pin

    def __repr__(self):
        return f"User(cnp={self._cnp}, name={self._first_name} {self._last_name})"
