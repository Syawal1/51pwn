###############################################################################
# OpenVAS Vulnerability Test
#
# ClamAV Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100651");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2015-06-17 14:03:59 +0530 (Wed, 17 Jun 2015)");
  script_name("ClamAV Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/clamd", 3310);

  script_tag(name:"summary", value:"Detects the installed version of
  ClamAV Anti Virus.

  This script sends a connection request to the server and try
  to get the version from the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("port_service_func.inc");

port = service_get_port(default:3310, proto:"clamd");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

req = string("VERSION\r\n");
send(socket:soc, data:req);
buf = recv(socket:soc, length:256);
close(soc);

if(!buf || "clamav" >!< tolower(buf))
  exit(0);

install = port + "/tcp";
version = "unknown";

# ClamAV 0.97.5
# ClamAV 0.100.3/25513/Wed Jul 17 08:15:42 2019
vers = eregmatch(pattern:"clamav ([0-9.]+)", string:tolower(buf));
if(vers[1])
  version = vers[1];

set_kb_item(name:"ClamAV/installed", value:TRUE);
set_kb_item(name:"ClamAV/remote/Ver", value:version);

cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:clamav:clamav:");
if(!cpe)
  cpe = "cpe:/a:clamav:clamav";

service_register(port:port, proto:"clamd");
register_product(cpe:cpe, location:install, port:port, service:"clamd");
log_message(data: build_detection_report(app:"ClamAV",
                                         version:version,
                                         install:install,
                                         cpe:cpe,
                                         concluded:vers[0]),
                                         port:port);
exit(0);
