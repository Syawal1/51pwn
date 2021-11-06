#!/bin/bash

# macOS stop  postgresql
brew services list
brew services stop postgresql
brew services stop redis

docker stop gvm
docker rm gvm
docker run -d -p 2222:22 -v `pwd`/_data:/data -e USERNAME="admin" -e PASSWORD="admin" -p 5432:5432 -p 9392:9392 -p 6379:6379 -p 9390:9390 -e TZ="Asia/Shanghai" -e SSHD="true" -e DB_PASSWORD="dbpassword" -e PASSWORD="strongpassword" --name gvm jweny/gvm-docker-20.08
# docker exec -it gvm /bin/bash
docker start gvm
docker logs -f gvm
docker ps -a|grep gvm|grep 'Exited' && docker start gvm
# docker exec -it gvm /bin/bash
# su -c greenbone-feed-sync --type GVMD_DATA gvm
# sh -c greenbone-feed-sync --type GVMD_DATA
# /bin/sh /usr/local/sbin/greenbone-feed-sync --type GVMD_DATA
# /usr/bin/rsync -ltvrP rsync://feed.community.greenbone.net:/data-objects/gvmd//timestamp /tmp/tmp.zB89PFE3y5
docker logs -f gvm

docker exec -it  gvm /bin/bash


open https://127.0.0.1:9392

docker stop scanner
docker rm scanner
docker run -d -v `pwd`/_data:/data -e MASTER_ADDRESS=docker.for.mac.localhost -e MASTER_PORT=2222 --name scanner jweny/gvm-scanner-docker-20.08
docker ps -a|grep scanner|grep 'Exited' && docker start scanner
docker logs -f scanner
