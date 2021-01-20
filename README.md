# synology-docker-api
Very basic API to connect to the docker package and Start/Stop/Restart or take json backups of your images.

###### Why?
I created this because sometimes my long running images would become stuck and needed a restart. I added this script onto my nas server and created a task to run it every day.

###### Examples:
python nas.py -i your.synology -p 443 -u user -p pass -t Restart -n Plex
python nas.py -i your.synology -p 443 -u user -p pass -t backup -o /Users/me/backups












Hi Mom!
