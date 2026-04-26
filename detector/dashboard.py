"""Live metrics dashboard (Flask).

Refreshes <= 3 seconds. Exposes banned IPs, global req/s, top 10 source IPs,
host CPU/memory, the effective mean/stddev driving detection, and uptime.
Served at the public domain configured in ``config.yaml``.
"""
