# =============================================================================
#  Anomaly-detector image.
#  Tiny Python 3.12 slim base; iptables installed so the blocker can call it
#  via subprocess. We deliberately stay on a single layer for the application
#  code to keep the rebuild cycle fast during the Stage 3 implementation push.
# =============================================================================

FROM python:3.12-slim AS runtime

# iptables is the binary the blocker shells out to; tini is a minimal init
# that reaps zombies and forwards signals so `docker stop` is graceful.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables tini ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so layer caching kicks in when only source
# files change.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy the daemon source.
COPY . /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# tini as PID 1, daemon as PID 2.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "main"]
