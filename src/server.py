import argparse


class Server:
    """
    A server class for managing connections and communications in a basic chat application.
    """

    def __init__(self, port):
        """
        Initialize the server with a specific port and default IP.
        """
        self.port = port
        self.ip = "127.0.0.1"
        self.user_info = {}

    def listen(self):
        pass


def parse_arguments():
    """
    Parse command line arguments for the server.
    """
    parser = argparse.ArgumentParser(description="Instant message exchange app, server side")
    parser.add_argument('-sp', type=int, help='Server port to bind')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    server = Server(args.sp)
    server.listen()
