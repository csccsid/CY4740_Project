import asyncio
import json


class TCPClientProtocol(asyncio.Protocol):
    def __init__(self, message, loop):
        self.message = message
        self.loop = loop
        self.on_conversation_done = asyncio.Event()

    def connection_made(self, transport):
        print(f'Send: {self.message}')
        transport.write(self.message.encode())

    def data_received(self, data):
        print(f'Received: {data.decode()}')
        self.on_conversation_done.set()

    def connection_lost(self, exc):
        print("Socket closed, stopping client")
        self.on_conversation_done.set()


async def main():
    loop = asyncio.get_running_loop()
    message = json.dumps({"action": "login", "username": "user1", "password": "pass123"})

    while True:
        try:
            coro = loop.create_connection(lambda: TCPClientProtocol(message, loop), '127.0.0.1', 12345)
            _, protocol = await coro
            await protocol.on_conversation_done.wait()
            protocol.on_conversation_done.clear()

            # Wait a bit before trying to send the message again or reconnect
            await asyncio.sleep(1)  # Adjust the sleep time as needed
        except KeyboardInterrupt:
            print("Client stopped by user.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            # Wait a bit before trying to reconnect, to handle transient network errors gracefully
            await asyncio.sleep(5)  # Adjust the sleep time as needed


asyncio.run(main())
