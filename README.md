# HNG Stage 3 — Anomaly Detection Engine

A real-time HTTP anomaly / DDoS detection daemon for a self-hosted Nextcloud
deployment. Tails Nginx access logs, learns baseline traffic, flags abnormal
behaviour, blocks offending IPs at the kernel level via `iptables`, and surfaces
live metrics on a public dashboard.

> Built as the DevOps Stage 3 task for the HNG Internship.

Full documentation, architecture, and runbook will live in this README as the
project takes shape.
