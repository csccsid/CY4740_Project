import threading
import time
from datetime import datetime, timedelta

KEY_CHECK_INTERVAL = 30  # in seconds
KEY_VALID_DURATION = 1800  # in seconds


class AuthenticationKeyManager:
    def __init__(self):
        self.authenticated_users = {}
        self.lock = threading.Lock()
        self.check_interval = KEY_CHECK_INTERVAL
        self.stopped = False
        threading.Thread(target=self.expire_keys_task).start()

    def add_user(self, username, dh_key, client_service_port, ttl_seconds=KEY_VALID_DURATION):
        """Add a new user with a specified TTL (time to live in seconds)."""
        expiry_time = datetime.now() + timedelta(seconds=ttl_seconds)
        with self.lock:
            self.authenticated_users[username] = {
                'dh_key': dh_key,
                'expiry_time': expiry_time,
                'client_service_port': client_service_port
            }

    def remove_user(self, username):
        """Remove a user by username."""
        with self.lock:
            if username in self.authenticated_users:
                del self.authenticated_users[username]

    def get_all_usernames(self):
        """Return a list of all usernames currently stored."""
        with self.lock:
            return list(self.authenticated_users.keys())

    def get_dh_key_by_username(self, username):
        """Retrieve the Diffie-Hellman key for a specific username."""
        with self.lock:
            if username in self.authenticated_users:
                return self.authenticated_users[username]['dh_key']
            else:
                return None  # Or raise an exception if preferred

    def expire_keys_task(self):
        """Background task to remove expired user entries."""
        while not self.stopped:
            with self.lock:
                current_time = datetime.now()
                # Create a list of usernames to delete to modify the dictionary during iteration
                to_delete = [user for user, data in self.authenticated_users.items() if
                             data['expiry_time'] <= current_time]
                for user in to_delete:
                    del self.authenticated_users[user]
                    print(f"Deleted {user}: Key expired.")
            time.sleep(self.check_interval)  # wait for the specified interval and then check again

    def stop(self):
        """Stop the background expiration task."""
        self.stopped = True

    def __del__(self):
        self.stop()
