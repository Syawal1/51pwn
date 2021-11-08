###############################################################################
# OpenVAS Vulnerability Test
#
# Pentaho Business Analytics Suite Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.808205");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-05-24 17:56:31 +0530 (Tue, 24 May 2016)");
  script_name("Pentaho Business Analytics Suite Version Detection (HTTP)");

  script_tag(name:"summary", value:"Detects the installed version of
  Pentaho Business Analytics Suite.

  This script sends and HTTP GET request and checks for the presence of
  Pentaho Business Analytics Suite from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:8080);

foreach dir(make_list_unique("/", "/pentaho", "/pentaho-solutions", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/") dir = "";

  res = http_get_cache(item:dir + "/Login", port:port);

  if("<title>Pentaho User Console - Login</title>" >< res &&
     ">User Name" >< res && ">Password" >< res &&
     "Pentaho Corporation" >< res) {

    version = "unknown";

    set_kb_item(name:"Pentaho/BA/Suite/Installed", value:TRUE);

    cpe = "cpe:/a:pentaho:business_analytics";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Pentaho Business Analytics (BA) Suite",
                                            version:version,
                                            install:install,
                                            cpe:cpe),
                port:port);
  }
}

exit(0);
