###############################################################################
# OpenVAS Vulnerability Test
#
# Mongoose Web Server Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813630");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-07-09 14:45:19 +0530 (Mon, 09 Jul 2018)");
  script_name("Mongoose Web Server Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Mongoose/banner");

  script_tag(name:"summary", value:"Detection of Mongoose Web Server.

  The script sends a connection request to the remote host and attempts to
  detect if the remote host is Mongoose Web Server and get the version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: Mongoose" >!< banner) exit(0);

version = "unknown";
install = port + "/tcp";

vers = eregmatch(string:banner, pattern:"Server: Mongoose/([0-9.]+)", icase:TRUE);
if(vers[1])
  version = vers[1];

set_kb_item(name:"Cesanta/Mongoose/installed", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:cesanta:mongoose:");
if(!cpe)
  cpe = "cpe:/a:cesanta:mongoose";

register_product(cpe:cpe, port:port, location:install, service:"www");
log_message(data:build_detection_report( app:"Cesanta Mongoose Embedded Web Server",
                                         version:version,
                                         install:install,
                                         cpe:cpe,
                                         concluded:vers[0]),
                                         port:port);

exit(0);
