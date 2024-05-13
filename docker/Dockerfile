# Ubuntu
FROM python:3.10.4

ENV PYTHONUNBUFFERED=1

LABEL io.figntigger.image.authors="christopher@hodgemcavaney.id.au" \
	maintainer="Christopher McAvaney <christopher@hodgemcavaney.id.au>" \
	description="A MQTT to RRD gateway"

# Ubuntu
# librrd-dev=1.7.2
RUN apt-get update \
	&& apt-get install -y librrd-dev=1.7.2-3+b7 --no-install-recommends \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# not required as the "pip install" below isn't using cache dir
# RUN pip install --upgrade pip

RUN adduser --disabled-password --no-create-home worker
WORKDIR /home/worker
RUN chown worker:worker . \
	&& touch /var/log/mqtt2rrd.log && chown worker:worker /var/log/mqtt2rrd.log
USER worker

COPY --chown=worker:worker requirements.txt ./
# to be mapped to a volume on running a container
COPY --chown=worker:worker mqtt2rrd-conf ./mqtt2rrd-conf

RUN pip install --user --no-cache-dir -r requirements.txt

# local version to this build
COPY --chown=worker:worker src/mqtt2rrd.py ./

CMD [ "python", "./mqtt2rrd.py", "--config_file", "./mqtt2rrd-conf/mqtt2rrd.conf", "start", "--no_daemon"]
HEALTHCHECK --start-period=10s --interval=10s CMD pgrep -x python > /dev/null || exit 1
