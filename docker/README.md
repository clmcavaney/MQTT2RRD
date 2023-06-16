Thoughts.

rrd-data - nfs volume from nas-01 - DONE

docker-compose to create docker volume that mounts that nfs volume - DONE

referencing see https://phoenixnap.com/kb/nfs-docker-volumes and https://stackoverflow.com/questions/39922161/mounting-nfs-shares-inside-docker-container

## Installation

1. Copy the `mqtt2rrd-conf-template` directory to `mqtt2rrd-conf`
2. Modify the mqtt2rrd.conf file to suit your needs
3. Build the docker image `docker-compose build`
4. Run the docker container `docker-compose up`

If you are happy things are working, then run detached `docker-compose up --detach`


