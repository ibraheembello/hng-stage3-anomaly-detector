"""Auto-release banned IPs on a backoff schedule.

Sequence: 10 min -> 30 min -> 2 h -> permanent. Each release removes the
iptables rule and emits a Slack notification via the notifier.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING


if TYPE_CHECKING:                      # pragma: no cover
    from blocker import Blocker, BanRecord
    from detector import Detector
    from notifier import Notifier


log = logging.getLogger(__name__)


class Unbanner:
    """Polls the blocker for expired bans and releases them.

    Single thread, polls every ``poll_interval`` seconds (default 5s).
    Releases trigger:
        1. iptables -D for the IP
        2. an UNBAN audit-log line
        3. a Slack notification
        4. clearing the detector's per-IP dedupe so a fresh ban can
           fire if the IP misbehaves again
    """

    def __init__(
        self,
        blocker: "Blocker",
        detector: "Detector",
        notifier: "Notifier",
        poll_interval: float = 5.0,
    ) -> None:
        self.blocker = blocker
        self.detector = detector
        self.notifier = notifier
        self.poll_interval = poll_interval

    def run(self, stop_event: threading.Event) -> None:
        log.info("unbanner thread started, poll_interval=%.1fs", self.poll_interval)
        while not stop_event.is_set():
            try:
                self._tick()
            except Exception:                       # pragma: no cover
                log.exception("unbanner tick failed; continuing")
            stop_event.wait(self.poll_interval)

    def _tick(self) -> None:
        for record in self.blocker.expired_bans():
            released = self.blocker.unban(record.ip, reason="scheduled-release")
            if released is None:
                continue
            self.detector.mark_unbanned(record.ip)
            self.notifier.send_unban(released)
