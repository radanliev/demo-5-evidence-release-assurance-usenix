# The witness container.
#
# Built so a witness can be separated from the collector by more than a process
# boundary. The container gets its own filesystem, PID, and network namespaces
# and a non-root user; the repository is mounted read-only, and the container is
# run with `--network none`, because a witness in this harness serves a local
# in-memory database and has no business reaching the network.
#
# What this does and does not buy is stated in the paper: it is separation by
# container on a single host and a single kernel. It is not a separate host or
# trust domain, and it does not defend against an adversary who is root on the
# host, who can reach the Docker socket, or who can attach a debugger from
# outside the container.
FROM python:3.12-slim

# Only what assurance/ actually imports. No build toolchain in the final image.
RUN pip install --no-cache-dir cryptography>=42.0.0 pyyaml>=6.0

# The witness never writes to the repository; it holds its key in memory and
# serves an in-memory SQLite database it builds at startup.
RUN useradd --create-home --uid 10001 witness
USER witness

WORKDIR /app
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python3", "specimens/witness_process.py"]
