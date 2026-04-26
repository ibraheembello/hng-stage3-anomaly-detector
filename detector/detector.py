"""Anomaly decision logic.

Maintains per-IP and global 60-second sliding-window deques. For each tick,
flags an actor as anomalous if its current rate produces a z-score above the
threshold OR exceeds ``baseline_mean * multiplier``. Tightens an IP's
thresholds when its 4xx/5xx rate is 3x the baseline error rate.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, Dict, Optional


log = logging.getLogger(__name__)


class AnomalyKind(str, Enum):
    PER_IP = "per_ip"
    GLOBAL = "global"


@dataclass
class AnomalyVerdict:
    """A decision returned by :meth:`Detector.evaluate`."""

    kind: AnomalyKind
    subject: str               # the IP, or "global"
    rate: float                # current observed rate
    baseline_mean: float
    baseline_stddev: float
    z_score: float
    condition: str             # human-readable trigger label


@dataclass
class _IPState:
    """Per-IP sliding window plus error tracking and tightening flag."""

    requests: Deque[float] = field(default_factory=deque)        # epoch seconds
    errors: Deque[float] = field(default_factory=deque)          # epoch seconds
    surge_active: bool = False
    last_seen: float = 0.0


class Detector:
    """Sliding-window anomaly detector.

    The class holds two kinds of state:

    * ``_global`` - a single deque of every request timestamp in the last
      ``window_seconds``. Used for the global rate signal.
    * ``_per_ip`` - one ``_IPState`` per source IP, also bounded to the
      same window. Stale IPs are evicted by ``_gc_locked``.

    A "tick" is the act of considering an IP. The natural cadence is
    "evaluate every IP that just produced a request" - we don't poll
    independently, we react.
    """

    def __init__(
        self,
        window_seconds: int,
        zscore_threshold: float,
        rate_multiplier: float,
        error_surge_multiplier: float,
        error_surge_zscore_factor: float,
        error_surge_rate_factor: float,
    ) -> None:
        self.window_seconds = window_seconds
        self.zscore_threshold = zscore_threshold
        self.rate_multiplier = rate_multiplier
        self.error_surge_multiplier = error_surge_multiplier
        self.error_surge_zscore_factor = error_surge_zscore_factor
        self.error_surge_rate_factor = error_surge_rate_factor

        self._global: Deque[float] = deque()
        self._per_ip: Dict[str, _IPState] = defaultdict(_IPState)
        # ``_already_flagged_ips`` prevents a single sustained burst from
        # producing a fresh ban every second; the blocker handles the ban
        # lifetime and tells us when the IP has been released.
        self._already_flagged_ips: set[str] = set()
        self._global_alert_window_until: float = 0.0

        self._lock = threading.Lock()

    # ---------------------------------------------------------------- API hooks

    def mark_unbanned(self, ip: str) -> None:
        """Called by the unbanner when a ban expires - clears the dedupe."""
        with self._lock:
            self._already_flagged_ips.discard(ip)

    # ----------------------------------------------------------- record + judge

    def record_and_evaluate(
        self,
        ip: str,
        timestamp: float,
        is_error: bool,
        baseline_mean: float,
        baseline_stddev: float,
        baseline_error_mean: float,
    ) -> Optional[AnomalyVerdict]:
        """Append the request and return a verdict if anything just fired.

        Returns ``None`` when the request is normal (the common case).
        """
        with self._lock:
            now = timestamp
            # ----- 1. evict everything older than the window -----------------
            cutoff = now - self.window_seconds
            self._evict_locked(self._global, cutoff)

            state = self._per_ip[ip]
            state.last_seen = now
            self._evict_locked(state.requests, cutoff)
            self._evict_locked(state.errors, cutoff)

            # ----- 2. record the new request ---------------------------------
            self._global.append(now)
            state.requests.append(now)
            if is_error:
                state.errors.append(now)

            # ----- 3. check for an error surge on this IP --------------------
            ip_error_rate = len(state.errors) / max(self.window_seconds, 1)
            state.surge_active = (
                baseline_error_mean > 0
                and ip_error_rate >= baseline_error_mean * self.error_surge_multiplier
            )

            # ----- 4. evaluate per-IP rate -----------------------------------
            ip_rate = len(state.requests) / max(self.window_seconds, 1)
            verdict = self._judge(
                kind=AnomalyKind.PER_IP,
                subject=ip,
                rate=ip_rate,
                baseline_mean=baseline_mean,
                baseline_stddev=baseline_stddev,
                surge=state.surge_active,
            )
            if verdict is not None and ip not in self._already_flagged_ips:
                self._already_flagged_ips.add(ip)
                return verdict

            # ----- 5. evaluate global rate -----------------------------------
            global_rate = len(self._global) / max(self.window_seconds, 1)
            global_verdict = self._judge(
                kind=AnomalyKind.GLOBAL,
                subject="global",
                rate=global_rate,
                baseline_mean=baseline_mean,
                baseline_stddev=baseline_stddev,
                surge=False,
            )
            if global_verdict is not None and now > self._global_alert_window_until:
                # Suppress repeat global alerts within the same window so
                # one spike doesn't generate a wall of Slack messages.
                self._global_alert_window_until = now + self.window_seconds
                return global_verdict

            return None

    # -------------------------------------------------------------- internals

    @staticmethod
    def _evict_locked(d: Deque[float], cutoff: float) -> None:
        """Drop every entry with timestamp <= ``cutoff`` from the front."""
        while d and d[0] <= cutoff:
            d.popleft()

    def _judge(
        self,
        kind: AnomalyKind,
        subject: str,
        rate: float,
        baseline_mean: float,
        baseline_stddev: float,
        surge: bool,
    ) -> Optional[AnomalyVerdict]:
        """Return a verdict if the rate is anomalous under the active rules."""
        zscore_threshold = self.zscore_threshold
        rate_multiplier = self.rate_multiplier
        if surge:
            # Tighten this actor's bar when its 4xx/5xx rate is elevated.
            zscore_threshold *= self.error_surge_zscore_factor
            rate_multiplier *= self.error_surge_rate_factor

        z = (rate - baseline_mean) / max(baseline_stddev, 1e-9)

        if z > zscore_threshold:
            return AnomalyVerdict(
                kind=kind, subject=subject, rate=rate,
                baseline_mean=baseline_mean, baseline_stddev=baseline_stddev,
                z_score=z,
                condition=f"z-score {z:.2f} > {zscore_threshold:.2f}"
                          + (" [error-surge tightened]" if surge else ""),
            )
        if rate > baseline_mean * rate_multiplier:
            return AnomalyVerdict(
                kind=kind, subject=subject, rate=rate,
                baseline_mean=baseline_mean, baseline_stddev=baseline_stddev,
                z_score=z,
                condition=f"rate {rate:.2f} > mean {baseline_mean:.2f} x {rate_multiplier:.2f}"
                          + (" [error-surge tightened]" if surge else ""),
            )
        return None

    # ---------------------------------------------------------------- snapshot

    def snapshot(self) -> dict:
        """Return a JSON-serialisable view used by the dashboard."""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            self._evict_locked(self._global, cutoff)
            global_rate = len(self._global) / max(self.window_seconds, 1)

            top_ips: list[tuple[str, int]] = []
            for ip, state in self._per_ip.items():
                self._evict_locked(state.requests, cutoff)
                if state.requests:
                    top_ips.append((ip, len(state.requests)))
            top_ips.sort(key=lambda kv: kv[1], reverse=True)

            return {
                "global_rate": global_rate,
                "top_ips": top_ips[:10],
                "tracked_ips": len(self._per_ip),
                "flagged_ips": list(self._already_flagged_ips),
            }

    def gc_stale(self, idle_seconds: int = 1800) -> int:
        """Drop per-IP state for IPs unseen in ``idle_seconds``."""
        cutoff = time.time() - idle_seconds
        with self._lock:
            stale = [ip for ip, s in self._per_ip.items() if s.last_seen < cutoff]
            for ip in stale:
                del self._per_ip[ip]
            return len(stale)
