import time
from collections import defaultdict, deque
from threading import Lock


class LoginRateLimiter:
    def __init__(self, max_attempts=5, window_seconds=300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = defaultdict(deque)
        self.lock = Lock()

    def is_blocked(self, key):
        now = time.monotonic()

        with self.lock:
            attempts = self.attempts[key]

            while attempts and now - attempts[0] >= self.window_seconds:
                attempts.popleft()

            return len(attempts) >= self.max_attempts

    def record_failure(self, key):
        now = time.monotonic()

        with self.lock:
            attempts = self.attempts[key]

            while attempts and now - attempts[0] >= self.window_seconds:
                attempts.popleft()

            attempts.append(now)

    def reset(self, key):
        with self.lock:
            self.attempts.pop(key, None)


login_limiter = LoginRateLimiter()
