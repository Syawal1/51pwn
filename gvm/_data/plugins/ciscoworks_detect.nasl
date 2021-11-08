###############################################################################
# OpenVAS Vulnerability Test
#
# CiscoWorks Management Console Detection
#
# Authors:
# Tenable Network Security
#
# Copyright:
# Copyright (C) 2006 TNS
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19559");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CiscoWorks Management Console Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 TNS");
  script_family("Product detection");
  # nb: Don't add a dependency to embedded_web_server_detect.nasl which has a dependency to this VT.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 1741);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host appears to be running CiscoWorks, a LAN Management Solution,
  on this port");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:1741 );

res = http_get_cache( item:"/login.html", port:port );

if( "<title>CiscoWorks</title>" >< res ) {
  log_message( port:port );
  http_set_is_marked_embedded( port:port );
}

exit( 0 );
