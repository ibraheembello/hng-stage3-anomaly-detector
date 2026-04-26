"""Deliver alerts to Slack via an incoming webhook.

Each alert includes the condition that fired, the current rate, the baseline
the rate is being compared against, the timestamp, and (for bans) the ban
duration.
"""
