#!/bin/bash

# macOS stop  postgresql
brew services list
brew services stop postgresql

docker run -d -p 2222:22 -v `pwd`/_data:/data  -p 5432:5432 -p 9392:9392 -p 6379:6379 -p 9390:9390 -e TZ="Asia/Shanghai" -e SSHD="true" -e DB_PASSWORD="dbpassword" -e PASSWORD="strongpassword" --name gvm jweny/gvm-docker-20.08
docker start gvm
docker logs -f gvm
