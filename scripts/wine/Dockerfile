# Wine runtime for exercising the Windows builds of AegisProxy on Linux (see README.md).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive WINEDEBUG=-all WINEPREFIX=/wineprefix
RUN apt-get update && apt-get install -y --no-install-recommends wine64 wine ca-certificates curl python3 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir /wineprefix && chown ubuntu /wineprefix
USER ubuntu
RUN (wine64 wineboot --init || wine wineboot --init); wineserver -w
