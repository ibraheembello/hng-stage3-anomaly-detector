"""Live metrics dashboard (Flask).

Refreshes <= 3 seconds. Exposes banned IPs, global req/s, top 10 source IPs,
host CPU/memory, the effective mean/stddev driving detection, and uptime.
Served at the public domain configured in ``config.yaml``.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict
from typing import TYPE_CHECKING

import psutil
from flask import Flask, jsonify, render_template_string

if TYPE_CHECKING:                      # pragma: no cover
    from baseline import Baseline
    from blocker import Blocker
    from detector import Detector


log = logging.getLogger(__name__)


_HTML = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="{{ refresh }}">
    <title>HNG Stage 3 - Anomaly Detector</title>
    <style>
        :root { color-scheme: dark; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            margin: 0; padding: 2rem 3rem;
            background: #0d1117; color: #c9d1d9;
        }
        h1 { margin: 0 0 .5rem 0; font-size: 1.5rem; }
        .sub { color: #8b949e; margin-bottom: 1.5rem; font-size: .85rem; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem;
        }
        .card {
            background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 1rem 1.2rem;
        }
        .card h2 {
            margin: 0 0 .8rem 0; font-size: .85rem;
            text-transform: uppercase; letter-spacing: .05em;
            color: #8b949e;
        }
        .big { font-size: 1.8rem; font-weight: 600; color: #58a6ff; }
        table { width: 100%; border-collapse: collapse; font-size: .9rem; }
        th, td { padding: .35rem .5rem; text-align: left; border-bottom: 1px solid #21262d; }
        th { color: #8b949e; font-weight: 500; }
        .banned { color: #f85149; font-family: 'SFMono-Regular', Consolas, monospace; }
        .ok { color: #3fb950; }
        .warn { color: #d29922; }
        footer { margin-top: 2rem; color: #6e7681; font-size: .8rem; }
        code { background:#21262d; padding: 1px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>HNG Stage 3 - Anomaly Detector</h1>
    <p class="sub">
        Public host: <code>{{ public_host }}</code>
        &middot; Auto-refresh every {{ refresh }}s
        &middot; Uptime: {{ uptime }}
    </p>

    <div class="grid">

        <div class="card">
            <h2>Global rate</h2>
            <div class="big">{{ "%.2f"|format(global_rate) }} <small>req/s</small></div>
            <div class="sub">over the last 60s sliding window</div>
        </div>

        <div class="card">
            <h2>Effective baseline</h2>
            <div>mean: <span class="big">{{ "%.2f"|format(baseline.mean) }}</span></div>
            <div>stddev: <strong>{{ "%.2f"|format(baseline.stddev) }}</strong></div>
            <div class="sub">
                samples={{ baseline.samples }}
                {% if baseline.hour_used is not none %}
                    &middot; hour-of-day slot: {{ baseline.hour_used }}
                {% else %}
                    &middot; rolling 30-min
                {% endif %}
            </div>
        </div>

        <div class="card">
            <h2>Host CPU / memory</h2>
            <div>CPU: <strong>{{ "%.1f"|format(cpu) }}%</strong></div>
            <div>Memory: <strong>{{ "%.1f"|format(mem) }}%</strong></div>
            <div class="sub">tracked IPs: {{ tracked_ips }}</div>
        </div>

        <div class="card">
            <h2>Banned IPs ({{ bans|length }})</h2>
            {% if bans %}
            <table>
                <tr><th>IP</th><th>#</th><th>Expires in</th></tr>
                {% for b in bans %}
                <tr>
                    <td class="banned">{{ b.ip }}</td>
                    <td>{{ b.ban_count }}</td>
                    <td>{{ b.remaining }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <div class="ok">no active bans</div>
            {% endif %}
        </div>

        <div class="card" style="grid-column: span 2;">
            <h2>Top 10 source IPs (last 60s)</h2>
            {% if top_ips %}
            <table>
                <tr><th>#</th><th>IP</th><th>Requests</th></tr>
                {% for ip, count in top_ips %}
                <tr>
                    <td>{{ loop.index }}</td>
                    <td>{{ ip }}</td>
                    <td>{{ count }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <div class="sub">idle</div>
            {% endif %}
        </div>

    </div>

    <footer>
        HNG DevOps Stage 3 &middot; built by <code>{{ public_host }}</code>
    </footer>
</body>
</html>
"""


def _format_remaining(expires_at: float | None) -> str:
    if expires_at is None:
        return "permanent"
    seconds = max(0, int(expires_at - time.time()))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


def _format_uptime(start: float) -> str:
    seconds = int(time.time() - start)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def build_app(
    *,
    detector: "Detector",
    baseline: "Baseline",
    blocker: "Blocker",
    public_host: str,
    refresh_interval: int,
    start_time: float,
) -> Flask:
    """Return a configured Flask app sharing state with the daemon."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        snap = detector.snapshot()
        bsnap = baseline.snapshot()
        bans = [
            {
                "ip": r.ip,
                "ban_count": r.ban_count,
                "remaining": _format_remaining(r.expires_at),
            }
            for r in blocker.all_bans()
            if r.expires_at is not None
        ]
        return render_template_string(
            _HTML,
            public_host=public_host,
            refresh=refresh_interval,
            uptime=_format_uptime(start_time),
            global_rate=snap["global_rate"],
            baseline=bsnap,
            cpu=psutil.cpu_percent(interval=None),
            mem=psutil.virtual_memory().percent,
            tracked_ips=snap["tracked_ips"],
            bans=bans,
            top_ips=snap["top_ips"],
        )

    @app.route("/api/metrics")
    def api_metrics():
        snap = detector.snapshot()
        bsnap = baseline.snapshot()
        return jsonify({
            "uptime_seconds": int(time.time() - start_time),
            "global_rate": snap["global_rate"],
            "tracked_ips": snap["tracked_ips"],
            "top_ips": snap["top_ips"],
            "baseline": asdict(bsnap),
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": psutil.virtual_memory().percent,
            "bans": [
                {
                    "ip": r.ip,
                    "ban_count": r.ban_count,
                    "expires_at": r.expires_at,
                    "condition": r.condition,
                }
                for r in blocker.all_bans()
                if r.expires_at is not None
            ],
        })

    return app


def run_dashboard(
    app: Flask,
    bind_host: str,
    bind_port: int,
    stop_event: threading.Event,   # noqa: ARG001 - kept for symmetry; werkzeug shutdown is handled by SIGTERM
) -> None:
    log.info("dashboard listening on %s:%d", bind_host, bind_port)
    # threaded=True so the auto-refresh page can be served while the
    # API endpoint is also being hit.
    app.run(host=bind_host, port=bind_port, threaded=True, use_reloader=False)
