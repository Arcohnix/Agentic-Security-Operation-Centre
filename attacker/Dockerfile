FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir requests

COPY attack.py /attack.py

CMD ["python3", "-u", "/attack.py"]
