Thoughts.

rrd-data - nfs volume from nas-01 - DONE
docker-compose to create docker volume that mounts that nfs volume - DONE
see - https://phoenixnap.com/kb/nfs-docker-volumes
and - https://stackoverflow.com/questions/39922161/mounting-nfs-shares-inside-docker-container

## Status
20220419

- A good start on this.
- Tested on timmy and then running on shawn.
- snap's confused me
  - I can't see the NFS mount on shawn as I could on timmy.  Something going on with the encapsulation of volumes (or something) in snaps I think.

More config and code cleanup required
