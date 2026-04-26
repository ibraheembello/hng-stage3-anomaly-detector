"""Entry point for the anomaly-detection daemon.

Wires up monitor, baseline, detector, blocker, unbanner, notifier, and dashboard
into a single long-running process. Loads configuration from ``config.yaml``
and runs each subsystem in its own thread.
"""
