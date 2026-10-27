# cljpass server: HTTP object store with SQLite.
# Please terminate TLS at a reverse proxy (see docker-compose.yml).
FROM docker.io/library/clojure:temurin-21-tools-deps-bookworm-slim AS build
WORKDIR /src
COPY deps.edn build.clj ./
RUN clojure -P && clojure -T:build clean
COPY src ./src
COPY resources ./resources
RUN clojure -T:build uber

FROM docker.io/library/eclipse-temurin:21-jre
# fixed UID/GID 10001 so that Kubernetes/Podman (fsGroup) can write to the volume
RUN groupadd --system --gid 10001 cljpass \
 && useradd --system --uid 10001 --gid 10001 --home /var/lib/cljpass --create-home cljpass
COPY --from=build /src/target/cljpass.jar /opt/cljpass/cljpass.jar
USER 10001:10001
VOLUME /var/lib/cljpass
EXPOSE 8080

# Set CLJPASS_INIT_TOKEN only for the initial setup, remove it afterwards.
# Optional single sign-on (Kerberos) for enrollment: mount the keytab and set
#   CLJPASS_KEYTAB=/etc/cljpass/http.keytab  CLJPASS_REALM=EXAMPLE.LOCAL
#   [CLJPASS_PRINCIPAL=HTTP/pw.example.local@EXAMPLE.LOCAL] [CLJPASS_REQUIRE_KERBEROS=1]
# CLJPASS_TRUST_PROXY=1: client address for the audit log from X-Forwarded-For.
ENTRYPOINT ["sh", "-c", "exec java -jar /opt/cljpass/cljpass.jar server --db /var/lib/cljpass/server.db --port 8080 --bind 0.0.0.0 ${CLJPASS_INIT_TOKEN:+--init-token $CLJPASS_INIT_TOKEN} ${CLJPASS_KEYTAB:+--keytab $CLJPASS_KEYTAB --realm $CLJPASS_REALM} ${CLJPASS_PRINCIPAL:+--principal $CLJPASS_PRINCIPAL} ${CLJPASS_REQUIRE_KERBEROS:+--require-kerberos} ${CLJPASS_TRUST_PROXY:+--trust-proxy}"]
