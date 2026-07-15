FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nginx \
    openssh-server \
    rsyslog \
    fail2ban \
    curl \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# ── Nginx: serve a realistic-looking site ──
COPY nginx.conf /etc/nginx/nginx.conf
COPY html/ /var/www/html/

# ── SSH: enable with weak config so brute-force attempts are real ──
RUN mkdir /var/run/sshd
RUN echo 'root:toor' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# ── Logging: structured JSON logs for the governance system ──
RUN mkdir -p /var/log/nginx /var/log/auth_structured

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80

ENTRYPOINT ["/entrypoint.sh"]
