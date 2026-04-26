"""Apply iptables DROP rules for banned IPs.

Idempotent: checks for an existing rule before inserting. Persists ban state
to disk so bans survive a daemon restart.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


log = logging.getLogger(__name__)


@dataclass
class BanRecord:
    """Persistent ban state for one IP."""

    ip: str
    banned_at: float                # epoch seconds
    expires_at: Optional[float]     # None means permanent
    ban_count: int                  # 1, 2, 3, ...
    condition: str                  # the rule that fired the ban
    rate: float
    baseline_mean: float


class Blocker:
    """Manages iptables DROP rules and the on-disk ban ledger.

    Why subprocess-out to ``iptables`` instead of using a Python netlink
    library: shelling out keeps the surface area small, makes the audit
    trail trivially reproducible, and matches what an SRE would type at
    the prompt during an incident.
    """

    # Backoff schedule, exposed as a class attribute so tests can override.
    DEFAULT_SCHEDULE: List[int] = [600, 1800, 7200]   # 10m, 30m, 2h, then permanent

    def __init__(
        self,
        iptables_chain: str,
        schedule_seconds: List[int],
        state_path: str,
        audit_log_path: str,
    ) -> None:
        self.chain = iptables_chain
        self.schedule = schedule_seconds or self.DEFAULT_SCHEDULE
        self.state_path = state_path
        self.audit_log_path = audit_log_path
        self._bans: Dict[str, BanRecord] = {}
        self._lock = threading.Lock()

        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)
        self._load_state()

    # -------------------------------------------------------------- iptables

    def _iptables(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["iptables", *args]
        return subprocess.run(
            cmd,
            check=check,
            capture_output=True,
            text=True,
        )

    def _rule_exists(self, ip: str) -> bool:
        """``iptables -C`` returns 0 when the rule exists, 1 otherwise."""
        result = self._iptables(
            "-C", self.chain, "-s", ip, "-j", "DROP", check=False,
        )
        return result.returncode == 0

    # -------------------------------------------------------------- public API

    def ban(
        self,
        ip: str,
        condition: str,
        rate: float,
        baseline_mean: float,
        now: Optional[float] = None,
    ) -> BanRecord:
        """Add the iptables rule and record the ban.

        Returns the freshly written :class:`BanRecord` so the notifier can
        include the ban duration in the Slack alert.
        """
        if now is None:
            now = time.time()

        with self._lock:
            existing = self._bans.get(ip)
            ban_count = (existing.ban_count + 1) if existing else 1

            duration = self._duration_for(ban_count)
            expires_at = (now + duration) if duration is not None else None

            if not self._rule_exists(ip):
                self._iptables("-I", self.chain, "-s", ip, "-j", "DROP")
                log.info("iptables DROP added for %s", ip)
            else:
                log.info("iptables DROP already present for %s; skipping insert", ip)

            record = BanRecord(
                ip=ip,
                banned_at=now,
                expires_at=expires_at,
                ban_count=ban_count,
                condition=condition,
                rate=rate,
                baseline_mean=baseline_mean,
            )
            self._bans[ip] = record
            self._save_state_locked()
            self._audit("BAN", record, duration_seconds=duration)
            return record

    def unban(self, ip: str, reason: str = "scheduled-release") -> Optional[BanRecord]:
        """Remove the iptables rule but KEEP the ban-count history.

        Keeping the count is what makes the backoff schedule work: when the
        same IP misbehaves again, we jump straight to the next tier.
        """
        with self._lock:
            existing = self._bans.get(ip)
            if existing is None:
                log.warning("unban requested for %s but no record exists", ip)
                return None

            if self._rule_exists(ip):
                self._iptables("-D", self.chain, "-s", ip, "-j", "DROP", check=False)
                log.info("iptables DROP removed for %s (%s)", ip, reason)

            existing.expires_at = None       # mark as currently un-banned
            self._save_state_locked()
            self._audit("UNBAN", existing, reason=reason)
            return existing

    def expired_bans(self, now: Optional[float] = None) -> List[BanRecord]:
        """Return ban records whose ``expires_at`` is in the past."""
        if now is None:
            now = time.time()
        with self._lock:
            return [
                r for r in self._bans.values()
                if r.expires_at is not None and r.expires_at <= now
            ]

    def all_bans(self) -> List[BanRecord]:
        with self._lock:
            return list(self._bans.values())

    def is_currently_banned(self, ip: str) -> bool:
        with self._lock:
            r = self._bans.get(ip)
            return r is not None and r.expires_at is not None

    # ---------------------------------------------------- backoff + persistence

    def _duration_for(self, ban_count: int) -> Optional[int]:
        """Return seconds for ban N, or ``None`` for permanent."""
        if ban_count - 1 < len(self.schedule):
            return self.schedule[ban_count - 1]
        return None

    def _save_state_locked(self) -> None:
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(
                {ip: asdict(r) for ip, r in self._bans.items()},
                f, indent=2,
            )
        os.replace(tmp, self.state_path)

    def _load_state(self) -> None:
        if not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self._bans = {ip: BanRecord(**vals) for ip, vals in raw.items()}
            log.info("loaded %d ban records from %s", len(self._bans), self.state_path)
        except (json.JSONDecodeError, TypeError) as exc:
            log.error("could not load ban state: %s; starting fresh", exc)
            self._bans = {}

    # --------------------------------------------------------------- audit log

    def _audit(
        self,
        action: str,
        record: BanRecord,
        duration_seconds: Optional[int] = None,
        reason: str | None = None,
    ) -> None:
        """Append one structured line to the audit log.

        Format mandated by the brief:
          [timestamp] ACTION ip | condition | rate | baseline | duration
        """
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
        if duration_seconds is None and record.expires_at is None:
            duration_repr = "permanent" if action == "BAN" else "released"
        elif duration_seconds is not None:
            duration_repr = f"{duration_seconds}s"
        else:
            remaining = max(0, int(record.expires_at - time.time())) if record.expires_at else 0
            duration_repr = f"{remaining}s"

        suffix = f" | reason={reason}" if reason else ""

        line = (
            f"[{ts}] {action} {record.ip} | {record.condition} | "
            f"rate={record.rate:.2f} | baseline={record.baseline_mean:.2f} | "
            f"duration={duration_repr}{suffix}\n"
        )
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(line)

    def audit_baseline(self, mean: float, stddev: float, samples: int, hour: int | None) -> None:
        """Audit-log a baseline recalculation event."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
        hour_repr = f"hour={hour}" if hour is not None else "rolling-30m"
        line = (
            f"[{ts}] BASELINE | {hour_repr} | "
            f"mean={mean:.2f} | stddev={stddev:.2f} | samples={samples}\n"
        )
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(line)
