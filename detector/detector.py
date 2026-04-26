"""Anomaly decision logic.

Maintains per-IP and global 60-second sliding-window deques. For each tick,
flags an actor as anomalous if its current rate produces a z-score above the
threshold OR exceeds ``baseline_mean * multiplier``. Tightens an IP's
thresholds when its 4xx/5xx rate is 3x the baseline error rate.
"""
