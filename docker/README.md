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


## Status
20220419

- A good start on this.
- Tested on timmy and then running on shawn.
- snap's confused me
  - I can't see the NFS mount on shawn as I could on timmy.  Something going on with the encapsulation of volumes (or something) in snaps I think.

More config and code cleanup required
