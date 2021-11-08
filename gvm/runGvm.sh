#!/bin/bash

# macOS stop  postgresql
brew services list
brew services stop postgresql
brew services stop redis

docker stop gvm
docker rm gvm
cd $HOMW/MyWork/51pwn/gvm
docker run -d -p 2222:22 -v `pwd`/_data:/data -e USERNAME="admin" -e PASSWORD="admin" -p 5432:5432 -p 9392:9392 -p 6379:6379 -p 9390:9390 -e TZ="Asia/Shanghai" -e SSHD="true" -e DB_PASSWORD="dbpassword" -e PASSWORD="strongpassword" --name gvm jweny/gvm-docker-20.08
# docker exec -it gvm /bin/bash
docker start gvm
docker logs -f gvm
docker ps -a|grep gvm|grep 'Exited' && docker start gvm
docker logs -f gvm
# docker exec -it gvm /bin/bash
# su -c greenbone-feed-sync --type GVMD_DATA gvm
# sh -c greenbone-feed-sync --type GVMD_DATA
# /bin/sh /usr/local/sbin/greenbone-feed-sync --type GVMD_DATA
# /usr/bin/rsync -ltvrP rsync://feed.community.greenbone.net:/data-objects/gvmd//timestamp /tmp/tmp.zB89PFE3y5

open https://0.0.0.0:9392/login

# 如果界面没有数据就进入更新
# docker exec -it  gvm /bin/bash


docker stop scanner
docker rm scanner
docker run -d -v `pwd`/_data:/data -e MASTER_ADDRESS=docker.for.mac.localhost -e MASTER_PORT=2222 --name scanner jweny/gvm-scanner-docker-20.08
docker ps -a|grep scanner|grep 'Exited' && docker start scanner
docker logs -f scanner

# https://git-lfs.github.com
brew install git-lfs
cd $HOME/MyWork/51pwn
git lfs install
find ./gvm -type f -size +10M |xargs -I % git lfs track %
git add  .gitattributes
git add gvm
git commit -m "add gvm" .
git push origin main
