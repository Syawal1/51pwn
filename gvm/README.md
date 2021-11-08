OpenVAS (open vulnerability assessment system) is an excellent and open source vulnerability detection tool

OpenVAS(Open Vulnerability Assessment System，开放式漏洞评估系统) 是一套优秀的、开源的漏洞检测工具

@see https://docs.greenbone.net/GSM-Manual/gos-21.04/en/GSM-Manual-GOS-21.04-en.pdf

# Run GVM（Greenbone Vulnerability Management）
OpenVAS has been renamed GVM (greenbone vulnerability management) since version 10. The latest version of GVM v20.8.0 is used in this paper. Therefore, the word "OpenVAS" no longer appears and is uniformly called GVM

OpenVAS从版本10开始，OpenVAS被改名为GVM（Greenbone Vulnerability Management），本文使用的是最新版的GVM v20.8.0，因此不再出现“OpenVAS”字样，统一叫GVM

# How to: Reset admin password for OpenVAS and GVM 11
<!-- https://dannyda.com/2020/08/26/how-to-reset-admin-password-for-openvas-and-gvm-11/?__cf_chl_captcha_tk__=xDh71zIdy_tf.E397Lakc6hPQO26.Q.gnvtfv1eUomA-1636207846-0-gaNycGzNB6U
-->
```
# 解决第一个坑：没有用户，加参数-e USERNAME="admin" -e PASSWORD="admin"  无效
$ docker exec -it gvm /bin/bash
# list all user
su gvm
gvmd --get-users
gvmd --get-roles
gvmd --create-user=admin --role=Admin
# change password
gvmd --user=admin --new-password=admin
```
<img width="768" alt="image" src="https://user-images.githubusercontent.com/18223385/140612985-6c643e31-3edf-4a2f-be7c-27b0c862493a.png">

# login
```
# 第二个坑：not use
https://0.0.0.0:9392
https://127.0.0.1:9392
# macOS use，用内网ip登陆，不要用127、localhost不然无法登陆 
open https://`ipconfig getifaddr en0`:9392
```
## 第三个坑：登陆后没有数据，需要各种手动更新
<img width="1203" alt="image" src="https://user-images.githubusercontent.com/18223385/140613295-78949ca7-c2d6-40fd-aeb9-9b668224335d.png">

@fix see https://wiki.archlinux.org/title/OpenVAS


```
### Update NVTs:
```
# 如果界面没有数据就进入更新
# docker exec -it  gvm /bin/bash

# fix： "pg_stat_tmp/global.stat": Operation not permitted
# chown -R postgres:postgres /data/database
# mkdir -p /var/lib/openvas
# chown -R gvm:gvm /var/lib/openvas
# su - gvm
$ greenbone-nvt-sync
# openvas --update-vt-info
```
### Update feeds:
# su - gvm
$ greenbone-feed-sync --type GVMD_DATA

### Update scapdata:
$ greenbone-scapdata-sync --type SCAP
$ greenbone-scapdata-sync --rsync  --progress --verbose
# or 解决rsync协议错误（其实多尝试若干次也行）：
# rsync: did not see server greeting；rsync error: error starting client-server protocol (code 5) at main.c(1675) [Receiver=3.1.3]
# 用 --wget相对稳妥，如果还不行，记得VPN科学上网
$ greenbone-scapdata-sync --wget --progress --verbose

### Update certdata:
$ greenbone-certdata-sync --type CERT
$ greenbone-certdata-sync --rsync  --progress --verbose
# or 和上面的更新不要同时运行，数据库要被锁
$ greenbone-certdata-sync --wget --progress --verbose
$ exit

$ docker logs -f gvm
```

# Thanks
- @jweny @jweny0 
- @fnmsd @lifr233
