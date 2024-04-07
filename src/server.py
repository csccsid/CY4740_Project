import argparse
import json
import socket
import logging
import struct

from util.db import db_connect
from util.msg_processing import recv_msg

logger = logging.getLogger(__name__)
logging.basicConfig(filename='server.log', encoding='utf-8', level=logging.DEBUG)


class Server:
    """
    A server class for managing connections and communications in a basic chat application.
    """

    def __init__(self, port, db_uri, db_keyfile_path):
        """
        Initialize the server with a specific port and default IP.
        """
        self.port = port
        self.host = "127.0.0.1"
        self.user_info = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((self.host, self.port))
        self.db = db_connect(db_uri, db_keyfile_path)

    def start(self):
        """
        Listen for incoming messages and handle different types of requests.
        """
        try:
            print(f"Server Initialized..., listening on port {self.port}")

            while True:
                message, addr = recv_msg(self.server_socket)
                print(message)
                pass

        except KeyboardInterrupt:
            print(f"Quitting IME server")
            exit(0)


def parse_arguments():
    """
    Parse command line arguments for the server.
    """
    parser = argparse.ArgumentParser(description="Instant message exchange app, server side")
    parser.add_argument('-sp', type=int, help='Server port to bind')
    parser.add_argument('-db_uri', type=str, help='The uri for mongodb database which stores user credentials')
    parser.add_argument('-db_key_path', type=str, help='Path to the key file for the mongodb database authentication')

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    server = Server(args.sp, args.db_uri, args.db_key_path)
    server.start()
