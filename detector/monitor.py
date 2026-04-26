"""Tail and parse the Nginx JSON access log line by line.

Yields one structured ``LogEvent`` per line (source_ip, timestamp, method,
path, status, response_size). Survives log rotation by re-opening the file
when its inode changes.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional


log = logging.getLogger(__name__)


@dataclass
class LogEvent:
    """Single Nginx access-log entry, post-parse."""

    source_ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    response_size: int

    @property
    def is_error(self) -> bool:
        """Server- or client-error response (4xx or 5xx)."""
        return self.status >= 400


def _open(path: str):
    """Open the log file at the end (the tail point) and return (fh, inode)."""
    fh = open(path, "r", encoding="utf-8", errors="replace")
    fh.seek(0, os.SEEK_END)
    inode = os.fstat(fh.fileno()).st_ino
    return fh, inode


def _parse(line: str) -> Optional[LogEvent]:
    """Return a ``LogEvent`` or ``None`` if the line is malformed.

    A malformed line (truncated JSON, partial write during a Compose
    rebuild, etc.) is logged and skipped rather than crashing the daemon.
    """
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        return LogEvent(
            source_ip=str(data["source_ip"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            method=str(data["method"]),
            path=str(data["path"]),
            status=int(data["status"]),
            response_size=int(data["response_size"]),
        )
    except (ValueError, KeyError, TypeError) as exc:
        log.warning("skipping malformed log line: %s | %r", exc, line[:200])
        return None


def tail(path: str, poll_interval: float = 0.1) -> Iterator[LogEvent]:
    """Yield ``LogEvent`` objects as new lines are appended to ``path``.

    Implemented as a poll-based tail (``readline()`` returns ``""`` on EOF;
    we sleep ``poll_interval`` and try again). Detects log rotation by
    comparing the open file's inode to the path's current inode and
    re-opens transparently.

    Generator design: callers can ``for event in tail(...)`` without ever
    blocking the main loop on threading primitives.
    """
    while not os.path.exists(path):
        log.info("waiting for log file to appear: %s", path)
        time.sleep(1.0)

    fh, inode = _open(path)
    log.info("tailing %s (inode=%s)", path, inode)

    try:
        while True:
            line = fh.readline()
            if line:
                event = _parse(line)
                if event is not None:
                    yield event
                continue

            # readline returned "" -> at EOF. Check for rotation.
            try:
                current_inode = os.stat(path).st_ino
            except FileNotFoundError:
                current_inode = None

            if current_inode is not None and current_inode != inode:
                log.info(
                    "log rotation detected (inode %s -> %s); reopening",
                    inode, current_inode,
                )
                fh.close()
                fh, inode = _open(path)
                # Read from the start of the new file.
                fh.seek(0, os.SEEK_SET)
                continue

            time.sleep(poll_interval)
    finally:
        fh.close()
