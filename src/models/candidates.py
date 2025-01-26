class Candidate:
    def __init__(self, code, name):
        self.code = code.upper()
        self.name = name

    def __str__(self):
        return f"{self.code}: {self.name}"
