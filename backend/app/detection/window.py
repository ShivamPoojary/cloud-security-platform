import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, Deque, Tuple, Optional


class SlidingWindowTracker:
    """Thread-safe in-memory sliding-window event tracker for stateful threshold detection.

    Tracks timestamps per (rule_id, entity_key) grouping.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # Key: (rule_id, entity_key) -> Deque of float timestamps (UTC epoch seconds)
        self._windows: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        # Tracks last alert timestamp to avoid alert storming within the same window
        self._last_alert: Dict[Tuple[str, str], float] = {}

    def record_and_check(
        self,
        rule_id: str,
        entity_key: str,
        event_time: datetime,
        window_seconds: int,
        threshold: int,
    ) -> bool:
        """Records an event occurrence and evaluates whether the threshold is met

        within the sliding time window.
        Returns True if threshold is breached (triggering an alert), False otherwise.
        """
        # Ensure UTC timestamp in epoch seconds
        if event_time.tzinfo is None:
            ts = event_time.replace(tzinfo=timezone.utc).timestamp()
        else:
            ts = event_time.timestamp()

        key = (str(rule_id), str(entity_key))
        cutoff = ts - window_seconds

        with self._lock:
            q = self._windows[key]
            # 1. Evict timestamps outside the window
            while q and q[0] <= cutoff:
                q.popleft()

            # 2. Record current timestamp
            q.append(ts)

            # 3. Check threshold condition
            if len(q) >= threshold:
                # Check cooldown: trigger alert only if no alert was triggered in the current sub-window
                last_trig = self._last_alert.get(key, 0.0)
                # Allow re-trigger only if threshold is satisfied and at least half the window has passed
                # or if this is the exact threshold hitting event
                if (ts - last_trig) >= (window_seconds / 2.0) or len(q) == threshold:
                    self._last_alert[key] = ts
                    return True

            return False

    def get_count(self, rule_id: str, entity_key: str, window_seconds: int, now: Optional[datetime] = None) -> int:
        """Returns the number of events in the active window for inspection/testing."""
        current_ts = (now or datetime.now(timezone.utc)).timestamp()
        cutoff = current_ts - window_seconds
        key = (str(rule_id), str(entity_key))

        with self._lock:
            q = self._windows.get(key)
            if not q:
                return 0
            while q and q[0] <= cutoff:
                q.popleft()
            return len(q)

    def clear(self):
        """Clears all sliding window state (used for test isolation)."""
        with self._lock:
            self._windows.clear()
            self._last_alert.clear()


# Global sliding window tracker instance
window_tracker = SlidingWindowTracker()
