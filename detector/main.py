"""Entry point for the anomaly-detection daemon.

Wires up monitor, baseline, detector, blocker, unbanner, notifier, and dashboard
into a single long-running process. Loads configuration from ``config.yaml``
and runs each subsystem in its own thread.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

import yaml

from baseline import Baseline
from blocker import Blocker
from dashboard import build_app, run_dashboard
from detector import AnomalyKind, Detector
from monitor import tail
from notifier import Notifier
from unbanner import Unbanner


log = logging.getLogger("hng.detector")


def _load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


def _make_baseline_loop(baseline: Baseline, blocker: Blocker, stop_event: threading.Event):
    """Wraps Baseline.run_recompute_loop so each tick is also audit-logged."""
    def loop() -> None:
        log.info("baseline thread started")
        while not stop_event.is_set():
            snap = baseline.recompute()
            blocker.audit_baseline(
                mean=snap.mean,
                stddev=snap.stddev,
                samples=snap.samples,
                hour=snap.hour_used,
            )
            stop_event.wait(baseline.recalc_interval)
    return loop


def _make_gc_loop(detector: Detector, stop_event: threading.Event, idle_seconds: int = 1800):
    def loop() -> None:
        log.info("detector GC thread started (idle_seconds=%d)", idle_seconds)
        while not stop_event.is_set():
            stop_event.wait(60)
            if stop_event.is_set():
                return
            removed = detector.gc_stale(idle_seconds=idle_seconds)
            if removed:
                log.info("GC: dropped %d stale per-IP states", removed)
    return loop


def main() -> int:
    _setup_logging()

    config_path = os.environ.get(
        "DETECTOR_CONFIG",
        str(Path(__file__).parent / "config.yaml"),
    )
    cfg = _load_config(config_path)
    log.info("loaded config from %s", config_path)

    # ------------------------------------------------------------------ wiring
    notifier = Notifier(webhook_url=os.environ.get(
        cfg["slack"]["webhook_env_var"], "",
    ))

    blocker = Blocker(
        iptables_chain=cfg["ban"]["iptables_chain"],
        schedule_seconds=cfg["ban"]["schedule_seconds"],
        state_path=cfg["ban"]["state_path"],
        audit_log_path=cfg["ban"]["audit_log_path"],
    )

    baseline = Baseline(
        window_seconds=cfg["baseline"]["window_seconds"],
        recalc_interval=cfg["baseline"]["recalc_interval_seconds"],
        hourly_min_samples=cfg["baseline"]["hourly_min_samples"],
        mean_floor=cfg["baseline"]["mean_floor"],
        stddev_floor=cfg["baseline"]["stddev_floor"],
    )

    detector = Detector(
        window_seconds=cfg["window"]["duration_seconds"],
        zscore_threshold=cfg["detection"]["zscore_threshold"],
        rate_multiplier=cfg["detection"]["rate_multiplier"],
        error_surge_multiplier=cfg["detection"]["error_surge_multiplier"],
        error_surge_zscore_factor=cfg["detection"]["error_surge_zscore_factor"],
        error_surge_rate_factor=cfg["detection"]["error_surge_rate_factor"],
    )

    unbanner = Unbanner(blocker=blocker, detector=detector, notifier=notifier)

    public_host = os.environ.get("PUBLIC_HOST", cfg["dashboard"]["public_host"])
    start_time = time.time()
    app = build_app(
        detector=detector,
        baseline=baseline,
        blocker=blocker,
        public_host=public_host,
        refresh_interval=cfg["dashboard"]["refresh_interval_seconds"],
        start_time=start_time,
    )

    # ------------------------------------------------------------------ threads
    stop_event = threading.Event()

    def _signal(_signo, _frame):
        log.info("signal received; shutting down")
        stop_event.set()

    signal.signal(signal.SIGTERM, _signal)
    signal.signal(signal.SIGINT, _signal)

    threads = [
        threading.Thread(
            target=_make_baseline_loop(baseline, blocker, stop_event),
            name="baseline", daemon=True,
        ),
        threading.Thread(
            target=unbanner.run, args=(stop_event,),
            name="unbanner", daemon=True,
        ),
        threading.Thread(
            target=_make_gc_loop(detector, stop_event),
            name="detector-gc", daemon=True,
        ),
        threading.Thread(
            target=run_dashboard,
            kwargs={
                "app": app,
                "bind_host": cfg["dashboard"]["bind_host"],
                "bind_port": cfg["dashboard"]["bind_port"],
                "stop_event": stop_event,
            },
            name="dashboard", daemon=True,
        ),
    ]
    for t in threads:
        t.start()

    # --------------------------------------------------------- monitor (main)
    log.info("starting monitor on %s", cfg["log"]["path"])
    try:
        for event in tail(cfg["log"]["path"]):
            if stop_event.is_set():
                break

            ts = event.timestamp.timestamp()
            baseline.record(ts, is_error=event.is_error)
            bsnap = baseline.snapshot()

            if blocker.is_currently_banned(event.source_ip):
                # IP is already banned at the kernel level; iptables
                # will drop their packets before they even reach Nginx.
                # If a packet still slipped through pre-rule, ignore it.
                continue

            verdict = detector.record_and_evaluate(
                ip=event.source_ip,
                timestamp=ts,
                is_error=event.is_error,
                baseline_mean=bsnap.mean,
                baseline_stddev=bsnap.stddev,
                baseline_error_mean=bsnap.error_mean,
            )
            if verdict is None:
                continue

            if verdict.kind is AnomalyKind.PER_IP:
                record = blocker.ban(
                    ip=verdict.subject,
                    condition=verdict.condition,
                    rate=verdict.rate,
                    baseline_mean=verdict.baseline_mean,
                )
                duration = (
                    int(record.expires_at - record.banned_at)
                    if record.expires_at is not None else None
                )
                notifier.send_ban(verdict, ban_count=record.ban_count, duration_seconds=duration)
            else:
                # GLOBAL anomaly - alert only, no ban.
                notifier.send_global(verdict)
    except KeyboardInterrupt:                       # pragma: no cover
        pass

    log.info("main loop exited; waiting for threads")
    stop_event.set()
    for t in threads:
        t.join(timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
