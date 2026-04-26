"""Rolling 30-minute baseline of per-second request counts.

Recomputes mean and stddev every 60 seconds. Maintains per-hour-of-day slots
and prefers the current hour's slot when it has enough samples. Applies a
configurable floor to the mean to avoid division-by-near-zero noise.
"""
