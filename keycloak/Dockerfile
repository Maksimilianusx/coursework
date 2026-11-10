FROM quay.io/keycloak/keycloak:26.8.1 AS builder
RUN /opt/keycloak/bin/kc.sh build --db=postgres --health-enabled=true --metrics-enabled=true --http-relative-path=/auth --http-management-relative-path=/
FROM quay.io/keycloak/keycloak:26.8.1
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY --chmod=755 start.sh /opt/keycloak/start.sh
COPY --chmod=755 health.sh /opt/keycloak/health.sh
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s CMD ["/opt/keycloak/health.sh"]
ENTRYPOINT ["/opt/keycloak/start.sh"]
