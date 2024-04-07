import json
import socket
import struct


def recv_msg(server_socket):
    """
    Receive a message from the client. Handles reading the message size and reconstructing the full message.
    """
    try:
        # first read the packet that includes the message size in its first 4 bytes
        packet, addr = server_socket.recvfrom(1024)  # as per ICMP standards
        message_size = struct.unpack('!I', packet[:4])[0]

        full_message = packet[4:]
        while len(full_message) < message_size:
            chunk, _ = server_socket.recvfrom(1024)
            full_message += chunk

        return json.loads(full_message.decode()), addr
    except (socket.error, ConnectionError, ConnectionResetError):
        print("Connection closed")
