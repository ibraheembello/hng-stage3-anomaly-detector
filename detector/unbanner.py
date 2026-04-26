"""Auto-release banned IPs on a backoff schedule.

Sequence: 10 min -> 30 min -> 2 h -> permanent. Each release removes the
iptables rule and emits a Slack notification via the notifier.
"""
