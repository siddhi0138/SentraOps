FROM prom/prometheus:v3.13.2 AS prom

FROM alpine:3.20
# gettext gives us envsubst - Prometheus's own config format has no env-var
# substitution, and the backend's public URL + Grafana Cloud credentials
# are only known at deploy time (Render env vars), not at build time.
RUN apk add --no-cache gettext

COPY --from=prom /bin/prometheus /bin/prometheus
COPY --from=prom /etc/prometheus/consoles /etc/prometheus/consoles
COPY --from=prom /etc/prometheus/console_libraries /etc/prometheus/console_libraries

COPY prometheus.yml.template /etc/prometheus/prometheus.yml.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
