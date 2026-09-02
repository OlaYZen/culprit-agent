# Culprit report-only agent — outbound-only, opens no listening ports.
#
# The agent monitors the HOST it runs on, so run the container in the host's PID
# and network namespaces (see docker-compose.yml / README). Sources that need
# the host's systemd (units, journal) or extra bind mounts degrade to an
# explicit "unavailable, because X" rather than breaking — the agent's honesty
# discipline is what makes a container deployment safe.
FROM python:3.12-slim

# iproute2 gives the agent `ip` for adapter/route detail. Everything else it
# needs is psutil + the standard library.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# psutil ships manylinux wheels for amd64/arm64, so no build toolchain is needed.
COPY requirements-agent.txt ./
RUN pip install --no-cache-dir -r requirements-agent.txt

COPY version.json ./
COPY culprit/ ./culprit/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Config comes from the environment (CULPRIT_HOST, CULPRIT_TOKEN, optional
# CULPRIT_INTERVAL / CULPRIT_INSECURE / CULPRIT_LOG_LEVEL); the entrypoint turns
# them into the agent's CLI arguments. `python -u` for unbuffered logs.
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
