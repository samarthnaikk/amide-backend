# Use official Ubuntu as base
FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y build-essential libpcap-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY netinfo.cpp ./
RUN g++ netinfo.cpp -lpcap -o netinfo
CMD ["./netinfo"]
