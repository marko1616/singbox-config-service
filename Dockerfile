FROM python:3.13-slim
ARG HTTP_PROXY
ARG HTTPS_PROXY
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
# Pinned amd64 tools. A different architecture fails explicitly, never silently.
RUN test "$(dpkg --print-architecture)" = amd64 && \
    curl --fail --location --retry 3 --max-time 180 -o /tmp/core.tgz https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64.tar.gz && \
    echo 'a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6  /tmp/core.tgz' | sha256sum -c - && \
    tar -xzf /tmp/core.tgz -C /tmp && \
    install -m 755 /tmp/sing-box-1.14.2-linux-amd64/sing-box /usr/local/bin/sing-box && \
    curl --fail --location --retry 3 --max-time 180 -o /tmp/converter.tgz https://github.com/rainbend/sing-box-subscribe-cli/releases/download/v1.0.4/sing-box-sub_v1.0.4_linux_amd64.tar.gz && \
    echo '4a1ffa6702bbed6e6d94265defbf610120a5e30ca397a78be1e7e0d4b819e04e  /tmp/converter.tgz' | sha256sum -c - && \
    tar -xzf /tmp/converter.tgz -C /tmp sing-box-sub && \
    install -m 755 /tmp/sing-box-sub /usr/local/bin/sing-box-sub && \
    rm -rf /tmp/core.tgz /tmp/converter.tgz /tmp/sing-box-1.14.2-linux-amd64 /tmp/sing-box-sub && \
    sing-box version
WORKDIR /app
COPY service.py /app/service.py
COPY data/geoip-foreign.srs /app/data/geoip-foreign.srs
EXPOSE 8787
CMD ["python3", "/app/service.py"]
