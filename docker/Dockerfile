# Ubuntu
FROM python:3.14-alpine

ENV PYTHONUNBUFFERED=1

LABEL io.figntigger.image.authors="christopher@hodgemcavaney.id.au" \
	maintainer="Christopher McAvaney <christopher@hodgemcavaney.id.au>" \
	description="A MQTT to RRD gateway" \
	org.opencontainers.image.description="A MQTT to RRD gateway" \
	org.opencontainers.image.authors="Christopher McAvaney <christopher@hodgemcavaney.id.au>"


# Alpine
# librrd-dev=1.7.2
RUN apk update \
	&& apk add --no-cache \
		procps \
		rrdtool-dev \
	&& apk add --no-cache --virtual build-dependencies \
		alpine-sdk \
		python3-dev \
		musl-dev \
		build-base \
	&& rm -rf /var/cache/apk/*

RUN adduser --disabled-password --no-create-home worker
WORKDIR /home/worker
RUN chown worker:worker . \
	&& touch /var/log/mqtt2rrd.log && chown worker:worker /var/log/mqtt2rrd.log

COPY --chown=worker:worker requirements.txt ./
# to be mapped to a volume on running a container
COPY --chown=worker:worker mqtt2rrd-conf ./mqtt2rrd-conf

# local version to this build
COPY --chown=worker:worker src/mqtt2rrd.py ./

RUN pip install --upgrade pip \
	&& pip install --no-cache-dir --requirement requirements.txt

RUN apk del --purge build-dependencies

USER worker

CMD [ "python", "./mqtt2rrd.py", "--config_file", "./mqtt2rrd-conf/mqtt2rrd.conf", "start", "--no_daemon"]
HEALTHCHECK --start-period=10s --interval=10s CMD pgrep -x python > /dev/null || exit 1

# vim: ts=4 sw=4
# END OF FILE
