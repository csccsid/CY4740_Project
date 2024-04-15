import threading
import time
import queue


def send_messages():
    while True:
        message = input("You: ")
        # Here, you would typically send the message over the network
        print(f"\033[AYou: {message}\033[K")  # \033[A moves the cursor up one line. \033[K clears the line.


def receive_messages():
    while True:
        # Simulated receiving of a message
        time.sleep(5)  # Simulate delay
        incoming_message = "Hello from the other side!"
        print(f"\r{incoming_message}\nYou: ", end="")


# Threads setup
thread_send = threading.Thread(target=send_messages)
thread_receive = threading.Thread(target=receive_messages)

thread_send.start()
thread_receive.start()

thread_send.join()
thread_receive.join()
