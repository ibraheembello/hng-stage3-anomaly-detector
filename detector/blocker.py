"""Apply iptables DROP rules for banned IPs.

Idempotent: checks for an existing rule before inserting. Persists ban state
to disk so bans survive a daemon restart.
"""
