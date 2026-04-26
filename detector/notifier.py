"""Deliver alerts to Slack via an incoming webhook.

Each alert includes the condition that fired, the current rate, the baseline
the rate is being compared against, the timestamp, and (for bans) the ban
duration.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

import requests

from detector import AnomalyVerdict


log = logging.getLogger(__name__)


def _format_duration(seconds: Optional[int]) -> str:
    if seconds is None:
        return "permanent"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


class Notifier:
    """Posts JSON payloads to a Slack incoming webhook.

    Slack's incoming webhooks accept up to 1 message per second per
    channel; we serialise sends through a lock plus a tiny minimum gap
    to stay well under the quota during a ban storm.
    """

    SEND_GAP = 0.25     # seconds between back-to-back Slack POSTs

    def __init__(self, webhook_url: str | None) -> None:
        self.webhook_url = webhook_url or ""
        self._lock = threading.Lock()
        self._last_send = 0.0

    # -------------------------------------------------------------- low level

    def _post(self, payload: dict) -> None:
        if not self.webhook_url:
            log.warning("Slack webhook not configured; dropping alert: %s", payload.get("text"))
            return

        with self._lock:
            elapsed = time.time() - self._last_send
            if elapsed < self.SEND_GAP:
                time.sleep(self.SEND_GAP - elapsed)
            try:
                response = requests.post(self.webhook_url, json=payload, timeout=5)
                if response.status_code >= 400:
                    log.error(
                        "Slack rejected alert: HTTP %d body=%s",
                        response.status_code, response.text[:200],
                    )
            except requests.RequestException as exc:
                log.error("Slack send failed: %s", exc)
            finally:
                self._last_send = time.time()

    @staticmethod
    def _ts() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))

    # --------------------------------------------------------------- ban / unban

    def send_ban(
        self,
        verdict: AnomalyVerdict,
        ban_count: int,
        duration_seconds: Optional[int],
    ) -> None:
        title = f":no_entry: BAN {verdict.subject}  (#{ban_count})"
        text = (
            f"*{title}*\n"
            f"`{verdict.condition}`\n"
            f"rate=*{verdict.rate:.2f}/s*  baseline_mean=*{verdict.baseline_mean:.2f}*  "
            f"stddev=*{verdict.baseline_stddev:.2f}*  z=*{verdict.z_score:.2f}*\n"
            f"duration=*{_format_duration(duration_seconds)}*\n"
            f"timestamp=`{self._ts()}`"
        )
        self._post({"text": text})

    def send_unban(self, record) -> None:
        text = (
            f":unlock: UNBAN {record.ip}  (ban #{record.ban_count})\n"
            f"original condition: `{record.condition}`\n"
            f"timestamp=`{self._ts()}`"
        )
        self._post({"text": text})

    # ---------------------------------------------------------------- global

    def send_global(self, verdict: AnomalyVerdict) -> None:
        text = (
            f":rotating_light: GLOBAL ANOMALY\n"
            f"`{verdict.condition}`\n"
            f"rate=*{verdict.rate:.2f}/s*  baseline_mean=*{verdict.baseline_mean:.2f}*  "
            f"stddev=*{verdict.baseline_stddev:.2f}*  z=*{verdict.z_score:.2f}*\n"
            f"timestamp=`{self._ts()}`"
        )
        self._post({"text": text})
