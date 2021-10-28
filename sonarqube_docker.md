```
# https://github.com/SonarSource/docker-sonarqube/blob/ee0ecba92f006f8429b7071acfef13207b3f4ddc/examples.md
# 在国外vps上1秒内完成，国内估计要好几个小时，总共500多M，所以可以先在vps上安装，再从vps上取过来会快很多很多
$ docker pull sonarqube
$ docker save sonarqube -o  sonarqube.iso  

# 在本地运行
$ scp -i ~/.ssh/id_rsa -r -P $myVpsPort root@51pwn.com:/root/sonarqube.iso .
$ docker load -i sonarqube.iso  
$ docker tag 9ff84ae48545 sonarqube:last 
# mac os为环境
$ brew reinstall postgresql
$ brew services restart postgresql
$ brew services list|grep postgres

# What is the default password for the user postgres?
# https://www.liquidweb.com/kb/what-is-the-default-password-for-postgresql/
$ cat /etc/passwd|grep postgres
_postgres:*:216:216:PostgreSQL Server:/var/empty:/usr/bin/false
 
$ vi /usr/local/var/postgres/pg_hba.conf
# IPv4 local connections:
host    all              all             127.0.0.1/32             ident
# IPv6 local connections:
host    all              all             ::1/128                  ident

$ brew services restart postgresql
# How to Create User in PostgreSQL
# https://ubiq.co/database-blog/create-user-postgresql/
$ psql postgres
create database sonar_db;
create user sonar with encrypted password 'sonar';
grant all privileges on database sonar_db to sonar;

$ docker stop sonarqube;docker rm sonarqube
$ docker run -d --name sonarqube \
    -p 9001:9001 -p 36697:36697 --rm \
    -e sonar.jdbc.username=sonar \
    -e sonar.jdbc.password=sonar \
    -e sonar.jdbc.url=jdbc:postgresql://docker.for.mac.localhost:5432/sonar_db \
    sonarqube:last

docker run -d --name sonarqube \
    -p 9001:9001 -p 9000:9000 -p 9092:9092 -p 36697:36697 --rm \
    sonarqube:last


$ docker ps -a|grep sonarqube
# https://hub.docker.com/_/sonarqube/
$ docker exec -it sonarqube /bin/bash
sysctl -w vm.max_map_count=524288
sysctl -w fs.file-max=131072
ulimit -n 131072
ulimit -u 8192

bash-5.1# nc -vv docker.for.mac.localhost 5432
docker.for.mac.localhost (192.168.65.2:5432) open


$ open 'http://127.0.0.1:9000/'
login: admin
password: admin


$ psql sonar_db sonar
psql: error: connection to server on socket "/tmp/.s.PGSQL.5432" failed: FATAL:  Peer authentication failed for user "sonar"

```
