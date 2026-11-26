"""In-memory sliding-window throttle for login and registration attempts.

Process-local by design: AVAP runs a single uvicorn worker (see
recover_interrupted_scans). With several workers each would keep its own
counts, which weakens but does not disable the protection.
"""

import threading
import time
from collections import defaultdict, deque


class SlidingWindowThrottle:
    """Counts events per key and reports when a key exceeds its limit."""

    def __init__(self, max_events: int, window_seconds: float):
        self._max_events = max_events
        self._window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        events = self._events[key]
        while events and now - events[0] > self._window_seconds:
            events.popleft()
        if not events:
            del self._events[key]
            return deque()
        return events

    def is_blocked(self, key: str) -> bool:
        """Return True if the key has reached its limit within the window."""
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= self._max_events

    def record(self, key: str) -> None:
        """Record one event for the key."""
        with self._lock:
            self._prune(key, time.monotonic())
            self._events[key].append(time.monotonic())

    def reset(self, key: str) -> None:
        """Forget all events for the key (e.g. after a successful login)."""
        with self._lock:
            self._events.pop(key, None)
