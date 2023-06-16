# Ubuntu
FROM python:3.10.4

ENV PYTHONUNBUFFERED=1

LABEL au.id.figntigger.image.authors="christopher@figntigger.id.au" \
	maintainer="Christopher McAvaney <christopher@figntigger.id.au>" \
	description="A MQTT to RRD gateway"

# Ubuntu
RUN apt-get update && \
	apt-get install -y librrd-dev

RUN pip install --upgrade pip

RUN adduser --disabled-password --no-create-home worker
WORKDIR /home/worker
RUN chown worker:worker .
RUN touch /var/log/mqtt2rrd.log && chown worker:worker /var/log/mqtt2rrd.log
USER worker

COPY --chown=worker:worker requirements.txt ./
# to be mapped to a volume on running a container
ADD --chown=worker:worker mqtt2rrd-conf-example ./mqtt2rrd-conf

RUN pip install --user --no-cache-dir -r requirements.txt

# local version to this build
COPY --chown=worker:worker ../src/mqtt2rrd.py ./

CMD [ "python", "./mqtt2rrd.py", "--config_file", "./mqtt2rrd-conf/mqtt2rrd.conf", "start", "--no_daemon"]
HEALTHCHECK --start-period=10s --interval=10s CMD pgrep -x python > /dev/null || exit 1
