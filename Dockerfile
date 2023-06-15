# Ubuntu
FROM python:3.10.4
# Alpine
#FROM python:3.10.4-alpine

ENV PYTHONUNBUFFERED=1

LABEL au.id.figntigger.image.authors="christopher@figntigger.id.au" \
	maintainer="Christopher McAvaney <christopher@figntigger.id.au>" \
	description="A MQTT to RRD gateway"

# Ubuntu
RUN apt-get update && \
	apt-get install -y librrd-dev
# Alpine
#RUN apk update \
#	&& apk add \
#		librrd \
#		rrdtool-dev \
#		python3-dev \
#		musl-dev \
#		linux-headers \
#		make

COPY requirements.txt ./
# to be mapped to a volume on running a container
ADD mqtt2rrd-conf-example ./mqtt2rrd-conf
RUN pip install --no-cache-dir -r requirements.txt

COPY mqtt2rrd.py ./

CMD [ "python", "./mqtt2rrd.py", "--config_file", "./mqtt2rrd-conf/mqtt2rrd.conf", "start", "--no_daemon"]
HEALTHCHECK --start-period=10s --interval=10s CMD pgrep -x python > /dev/null || exit 1
