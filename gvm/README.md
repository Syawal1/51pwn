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
docker exec -it gvm /bin/bash

# list all user
su gvm
gvmd --get-users
gvmd --get-roles
gvmd --create-user=admin --role=Admin
# change password
gvmd --user=admin --new-password=admin
```
<img width="768" alt="image" src="https://user-images.githubusercontent.com/18223385/140612985-6c643e31-3edf-4a2f-be7c-27b0c862493a.png">

# Thanks
@fnmsd
