###############################################################################
# OpenVAS Vulnerability Test
#
# Dell OpenManage Server Administrator Remote Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807563");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-04-27 10:47:16 +0530 (Wed, 27 Apr 2016)");
  script_name("Dell OpenManage Server Administrator Remote Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of Dell OpenManage Server Administrator.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 1311);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

omsaPort = http_get_port(default:1311);

foreach dir (make_list("/", "/servlet"))
{
  install = dir;
  if( dir == "/" ) dir = "";

  omsaReq = http_get(item: string(dir, "/Login?omacmd=getlogin&page=Login&managedws=true"), port:omsaPort);
  omsaRes = http_keepalive_send_recv(port:omsaPort, data:omsaReq);

  if('application">Server Administrator' >< omsaRes && '>Login' >< omsaRes &&
     'dell' >< omsaRes)
  {
    url =  dir + "/UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin";
    omsaReq = http_get(item: url, port:omsaPort);
    omsaRes = http_keepalive_send_recv(port:omsaPort, data:omsaReq);

    vers = eregmatch(pattern:'class="desc25">Version ([0-9.]+)' , string:omsaRes);
    if(vers[1]){
      omsaVer = vers[1];
    } else {
      omsaVer = "Unknown";
    }

    set_kb_item(name:"Dell/OpenManage/Server/Administrator/Installed", value:TRUE);

    cpe = build_cpe(value:omsaVer, exp:"^([0-9.]+)", base:"cpe:/a:dell:openmanage_server_administrator:");
    if(!cpe)
      cpe= "cpe:/a:dell:openmanage_server_administrator";

    register_product(cpe:cpe, location:install, port:omsaPort, service:"www");

    log_message(data: build_detection_report(app: "Dell OpenManage Server Administrator",
                                             version: omsaVer,
                                             install: install,
                                             cpe: cpe,
                                             concluded: vers[0], concludedUrl: url),
                port: omsaPort);
    exit(0);
  }
}
