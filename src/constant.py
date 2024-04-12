from math import pi

"""
op codes
"""
OP_ERROR = 0
OP_LOGIN = 1
OP_LOGOUT = 2
OP_AUTH = 3
OP_CMD = 4
OP_MSG = 5


"""
Server config
"""
SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 12345


"""
Diffie–Hellman key config
"""
P = 2 ** 768 - 2 ** 704 - 1 + 2 ** 64 * (int(2 ** 638 * pi) + 149686)
G = 2