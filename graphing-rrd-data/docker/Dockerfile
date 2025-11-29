# Ubuntu
FROM python:3.14-alpine
RUN set -x \
	&& apk add --no-cache go
RUN go install github.com/aptible/supercronic@v0.2.1

LABEL io.figntigger.image.authors="christopher@hodgemcavaney.id.au" \
	maintainer="Christopher McAvaney <christopher@hodgemcavaney.id.au>" \
	description="Graphing renderer for the MQTT2RRD service" \
	org.opencontainers.image.description="Graphing renderer for the MQTT2RRD service" \
	org.opencontainers.image.authors="Christopher McAvaney <christopher@hodgemcavaney.id.au>"

FROM python:3.14-alpine
# Alpine
# librrd-dev=1.7.2
RUN apk update \
	&& apk add --no-cache \
		procps \
		shadow \
		bash \
		rrdtool \
	&& rm -rf /var/cache/apk/*

RUN adduser --disabled-password --no-create-home worker
WORKDIR /home/worker
RUN chown worker:worker .
RUN pip install --upgrade pip \
	&& pip install --no-cache-dir --break-system-packages awscli

COPY --from=0 /root/go/bin/supercronic /usr/local/bin/supercronic
COPY --chown=worker:worker crontab .
COPY --chown=worker:worker --exclude=docker*/ graphing-rrd-data ./graphing-rrd-data

USER worker

ENTRYPOINT [ "supercronic", "crontab" ]
HEALTHCHECK --start-period=10s --interval=10s CMD pgrep -x supercronic > /dev/null || exit 1

# vim: ts=4 sw=4
# END OF FILE
