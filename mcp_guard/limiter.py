import time
import threading
from typing import Dict, Tuple, Optional
from dataclasses import dataclass


@dataclass
class ToolRatePolicy:
    rate_per_minute: float
    burst_capacity: float


class TokenBucket:
    """
    Single TokenBucket instance using time.monotonic() to eliminate wall-clock drift.
    """

    def __init__(self, capacity: float, refill_per_sec: float):
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._tokens = float(capacity)
        self._last_time = time.monotonic()

    def consume(self, amount: float = 1.0) -> Tuple[bool, float]:
        """
        Attempt to consume tokens.
        Returns: (allowed: bool, retry_after_seconds: float)
        """
        now = time.monotonic()
        elapsed = now - self._last_time
        self._last_time = now

        # Refill tokens capped at capacity
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_sec)

        if self._tokens >= amount:
            self._tokens -= amount
            return True, 0.0

        shortage = amount - self._tokens
        retry_after = shortage / self.refill_per_sec if self.refill_per_sec > 0 else 60.0
        return False, max(0.01, retry_after)


class PerToolRateLimiter:
    """
    Per-(caller, tool_class) hierarchical rate limiter.
    - Differentiates light (e.g. search) vs heavy (e.g. generate/ask) tools.
    - Memory bounded: LRU-style idle client eviction.
    - Thread-safe token consumption.
    """

    def __init__(
        self,
        default_policy: ToolRatePolicy = ToolRatePolicy(rate_per_minute=60, burst_capacity=20),
        tool_policies: Optional[Dict[str, ToolRatePolicy]] = None,
        max_buckets: int = 5000,
        idle_timeout_seconds: float = 3600.0,
    ):
        self.default_policy = default_policy
        self.tool_policies = tool_policies or {}
        self.max_buckets = max_buckets
        self.idle_timeout_seconds = idle_timeout_seconds

        self._buckets: Dict[Tuple[str, str], Tuple[TokenBucket, float]] = {}  # (caller, tool) -> (bucket, last_access)
        self._lock = threading.Lock()

    def get_policy(self, tool_name: str) -> ToolRatePolicy:
        return self.tool_policies.get(tool_name, self.default_policy)

    def check(self, caller_id: str, tool_name: str, rate_multiplier: float = 1.0) -> Tuple[bool, float]:
        """
        Check rate limit and consume 1 token.
        Returns (allowed, retry_after_seconds).
        """
        now = time.monotonic()
        key = (caller_id, tool_name)
        policy = self.get_policy(tool_name)

        effective_rate = (policy.rate_per_minute / 60.0) * max(0.1, rate_multiplier)
        effective_capacity = policy.burst_capacity * max(0.1, rate_multiplier)

        with self._lock:
            # Periodic prune if exceeding capacity
            if len(self._buckets) >= self.max_buckets:
                self._prune_stale(now)

            if key not in self._buckets:
                bucket = TokenBucket(effective_capacity, effective_rate)
            else:
                bucket, _ = self._buckets[key]

            allowed, retry_after = bucket.consume(1.0)
            self._buckets[key] = (bucket, now)
            return allowed, retry_after

    def _prune_stale(self, now: float) -> None:
        """Evict stale buckets when near threshold."""
        stale_keys = [
            k for k, (_, last_seen) in self._buckets.items()
            if (now - last_seen) > self.idle_timeout_seconds
        ]
        for k in stale_keys:
            del self._buckets[k]

        # Hard limit safeguard
        if len(self._buckets) >= self.max_buckets:
            sorted_by_age = sorted(self._buckets.items(), key=lambda item: item[1][1])
            excess = len(self._buckets) - int(self.max_buckets * 0.8)
            for k, _ in sorted_by_age[:excess]:
                del self._buckets[k]
