FROM alpine:latest
# iproute2 brings `tc`, used by the latency and packet-loss scenarios (issue #25)
RUN apk add --no-cache iptables iproute2
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
