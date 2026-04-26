"""Tail and parse the Nginx JSON access log line by line.

Yields one structured ``LogEvent`` per line (source_ip, timestamp, method,
path, status, response_size). Survives log rotation by re-opening the file
when its inode changes.
"""
