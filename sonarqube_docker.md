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

$ cat /usr/local/var/postgres/pg_hba.conf|grep -Ev '^#'
local   all             all                                     peer
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5
local   replication     all                                     md5
host    replication     all             127.0.0.1/32            md5
host    replication     all             ::1/128                 ident

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
    -p 9000:9000  --rm \
    -e sonar.jdbc.username=sonar \
    -e sonar.jdbc.password=sonar \
    -e sonar.jdbc.url=jdbc:postgresql://docker.for.mac.localhost:5432/sonar_db \
    sonarqube:last


docker run -d --name sonarqube --pull always \
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

# https://stackoverflow.com/questions/13410686/postgres-could-not-connect-to-server
$ ls -l /tmp/.s.PGSQL.5432
srwxrwxrwx  1 51pwn  wheel  0 10 28 16:37 /tmp/.s.PGSQL.5432
51pwn@192 testiiop12.2.1.3.0 $  grep unix_socket /usr/local/var/postgres/postgresql.conf
#unix_socket_directories = '/tmp'       # comma-separated list of directories
#unix_socket_group = ''                 # (change requires restart)
unix_socket_permissions = 0777          # begin with 0 to use octal notation


$ rm /usr/local/var/postgres/postmaster.pid
$ brew services restart postgresql

# https://stackoverflow.com/questions/18555352/password-authentication-failed-for-user-postgres-on-mac
$ vi /usr/local/var/postgres/pg_hba.conf
local   all             all                                     peer

# FATAL: Ident authentication failed for user "sonar"
$ vi /usr/local/var/postgres/pg_hba.conf 
# IPv4 local connections:
host    all             all             127.0.0.1/32            md5
# IPv6 local connections:
host    all             all             ::1/128                 md5
# Allow replication connections from localhost, by a user with the
# replication privilege.
local   replication     all                                     md5
host    replication     all             127.0.0.1/32            md5

brew services restart postgresql
# 确认状态
brew services list|grep postgres
sudo passwd  _postgres
_postgres
_postgres
sudo su _postgres -c passwd

psql template1
ALTER USER sonar WITH PASSWORD 'sonar';

$ psql sonar_db -U sonar -h localhost
Password for user sonar: 
psql (14.0)
Type "help" for help.

sonar_db=> \q

```
