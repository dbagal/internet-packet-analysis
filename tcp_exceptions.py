
class NoTCPTransactions(Exception):
    def __init__(self):
        msg = f"No transactions exist after connection setup!"
        super().__init__(msg)