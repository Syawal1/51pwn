# OpenVAS Vulnerability Test
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11120");
  script_version("2020-11-11T14:11:33+0000");
  script_tag(name:"last_modification", value:"2020-11-11 14:11:33 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("xtelw Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1314);

  script_tag(name:"summary", value:"xteld is running on this port in HyperTerminal mode.

  This service allows users to connect to the 'Teletel' network. Some of the servers are expensive.

  Note that by default, xteld forbids access to the most expensive services.");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("string_hex_func.inc");

port = unknownservice_get_port(default:1314);

banner = unknown_banner_get(port:port, dontfetch:FALSE);
if(!banner)
  exit(0);

# I'm too lazy to parse the service list :-)
if("Service Minitel" >< banner && "Xteld" >< banner) {
  log_message(port:port);
  service_register(port:port, proto:"xtelw");
}

exit(0);
