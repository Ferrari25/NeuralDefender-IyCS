# Respaldo diario cifrado (RQ-SEC-05). Ver respaldo.sh.
FROM alpine:3.20

# Falso positivo DL3018: la base está fijada (alpine:3.20); fijar cada paquete apk rompería el
# build cuando Alpine rote versiones dentro de la misma rama.
# hadolint ignore=DL3018
RUN apk add --no-cache bash coreutils curl findutils openssl tar tzdata

COPY backup/*.sh /backup/
RUN chmod 755 /backup/*.sh

# Sin privilegios. docker-compose.yml fija el UID/GID real (el del dueño de
# los directorios montados en el host) con `user:`; este es el valor por defecto.
USER 1000:1000

CMD ["/backup/programador.sh"]
