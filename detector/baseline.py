"""Rolling 30-minute baseline of per-second request counts.

Recomputes mean and stddev every 60 seconds. Maintains per-hour-of-day slots
and prefers the current hour's slot when it has enough samples. Applies a
configurable floor to the mean to avoid division-by-near-zero noise.
"""

from __future__ import annotations

import logging
import math
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Tuple


log = logging.getLogger(__name__)


@dataclass
class BaselineSnapshot:
    """A baseline reading captured at a specific instant."""

    mean: float
    stddev: float
    error_mean: float          # baseline 4xx/5xx rate per second
    samples: int               # sample count behind ``mean``
    hour_used: int | None      # hour-of-day if the hourly slot was chosen, else None


class Baseline:
    """Rolling baseline of per-second request counts.

    Two parallel histories are kept:

    1. ``_global`` - a deque of the last ``window_seconds`` per-second
       totals, regardless of hour.
    2. ``_hourly`` - one deque per hour-of-day (0-23) for the same window
       length. The hourly slot wins when it has more than
       ``hourly_min_samples`` entries; this keeps a 3am baseline from being
       polluted by 3pm traffic and vice versa.

    The class is fed one increment per request via ``record(timestamp,
    is_error)`` and recomputed periodically by ``recompute()``.
    """

    def __init__(
        self,
        window_seconds: int,
        recalc_interval: int,
        hourly_min_samples: int,
        mean_floor: float,
        stddev_floor: float,
    ) -> None:
        self.window_seconds = window_seconds
        self.recalc_interval = recalc_interval
        self.hourly_min_samples = hourly_min_samples
        self.mean_floor = mean_floor
        self.stddev_floor = stddev_floor

        # Per-second counters being filled right now.
        self._current_second: int = int(time.time())
        self._current_count: int = 0
        self._current_errors: int = 0

        # History of (count, errors) for each whole second in the window.
        self._global: Deque[Tuple[int, int]] = deque(maxlen=window_seconds)
        self._hourly: Dict[int, Deque[Tuple[int, int]]] = defaultdict(
            lambda: deque(maxlen=window_seconds)
        )

        # Last computed snapshot. Reads are atomic by virtue of GIL +
        # the snapshot being a frozen dataclass.
        self._snapshot = BaselineSnapshot(
            mean=mean_floor,
            stddev=stddev_floor,
            error_mean=0.0,
            samples=0,
            hour_used=None,
        )

        self._lock = threading.Lock()

    # ------------------------------------------------------------------ ingestion

    def record(self, timestamp: float, is_error: bool) -> None:
        """Account one observed request at ``timestamp`` (epoch seconds)."""
        sec = int(timestamp)
        with self._lock:
            if sec == self._current_second:
                self._current_count += 1
                if is_error:
                    self._current_errors += 1
                return

            # Time has moved on - close out the bucket we were filling
            # and seal any silent seconds with zero-count buckets so
            # gaps don't get hidden.
            self._flush_locked(up_to=sec)
            self._current_second = sec
            self._current_count = 1 if not is_error else 1
            self._current_errors = 1 if is_error else 0

    def _flush_locked(self, up_to: int) -> None:
        """Push the current bucket and zero-fill missing seconds.

        Caller must hold ``self._lock``.
        """
        # Push the bucket we were accumulating in.
        bucket = (self._current_count, self._current_errors)
        self._global.append(bucket)
        hour = time.gmtime(self._current_second).tm_hour
        self._hourly[hour].append(bucket)

        # Walk forward until the second before ``up_to``, filling silent
        # seconds with zeros. Cap the loop so a long quiet period doesn't
        # spend time appending thousands of zero buckets when the maxlen
        # would discard them anyway.
        gap = min(up_to - self._current_second - 1, self.window_seconds + 1)
        for offset in range(1, gap + 1):
            silent_sec = self._current_second + offset
            self._global.append((0, 0))
            self._hourly[time.gmtime(silent_sec).tm_hour].append((0, 0))

    # --------------------------------------------------------------- computation

    def recompute(self) -> BaselineSnapshot:
        """Recompute mean and stddev from history; persist as snapshot."""
        with self._lock:
            # Make sure no started-but-never-closed bucket is lost when
            # traffic stops. Flush the current bucket forward to "now".
            now = int(time.time())
            if now > self._current_second:
                self._flush_locked(up_to=now)
                self._current_second = now
                self._current_count = 0
                self._current_errors = 0

            current_hour = time.gmtime(now).tm_hour
            hourly_history = self._hourly.get(current_hour)

            if hourly_history is not None and len(hourly_history) >= self.hourly_min_samples:
                history = list(hourly_history)
                hour_used: int | None = current_hour
            else:
                history = list(self._global)
                hour_used = None

        if not history:
            snapshot = BaselineSnapshot(
                mean=self.mean_floor,
                stddev=self.stddev_floor,
                error_mean=0.0,
                samples=0,
                hour_used=hour_used,
            )
        else:
            counts = [c for c, _ in history]
            errors = [e for _, e in history]
            mean = max(statistics.fmean(counts), self.mean_floor)
            error_mean = statistics.fmean(errors)
            if len(counts) > 1:
                stddev = max(statistics.stdev(counts), self.stddev_floor)
            else:
                stddev = self.stddev_floor
            snapshot = BaselineSnapshot(
                mean=mean,
                stddev=stddev,
                error_mean=error_mean,
                samples=len(history),
                hour_used=hour_used,
            )

        log.info(
            "baseline recomputed: mean=%.2f stddev=%.2f error_mean=%.4f "
            "samples=%d hour_used=%s",
            snapshot.mean, snapshot.stddev, snapshot.error_mean,
            snapshot.samples, snapshot.hour_used,
        )
        self._snapshot = snapshot
        return snapshot

    def snapshot(self) -> BaselineSnapshot:
        """Return the latest computed snapshot without recomputing."""
        return self._snapshot

    # ------------------------------------------------------------ recompute loop

    def run_recompute_loop(self, stop_event: threading.Event) -> None:
        """Block until ``stop_event``, recomputing every ``recalc_interval``s."""
        while not stop_event.is_set():
            self.recompute()
            stop_event.wait(self.recalc_interval)
