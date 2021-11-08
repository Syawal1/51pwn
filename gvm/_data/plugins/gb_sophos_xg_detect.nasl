# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105625");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-04-27 12:36:42 +0200 (Wed, 27 Apr 2016)");

  script_name("Sophos XG Firewall Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 4444);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:4444 );

url = "/webconsole/webpages/login.jsp";
buf = http_get_cache( item:url, port:port );

if( buf !~ "^HTTP/1\.[01] 200" || "<title>Sophos</title>" >!< buf )
  exit( 0 );

url1 = "/javascript/lang/English/common.js";
buf1 = http_get_cache( item:url1, port:port );
if( buf1 !~ "Sophos [^ ]*Firewall" )
  exit( 0 );

set_kb_item( name:"sophos/xg_firewall/detected", value:TRUE );

version = "unknown";
cpe = "cpe:/o:sophos:xg_firewall_firmware";

# example: ver=17.5.10.620 (620 seems to be the "build")
vers = eregmatch( pattern:'ver=([0-9]+\\.[^"\' ]+)', string:buf );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  cpe += ":" + version;
  concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
}

register_and_report_os( os:"Sophos XG Firewall Firmware", cpe:cpe, desc:"Sophos XG Firewall Detection (HTTP)", runs_key:"unixoide" );

register_product( cpe:cpe, location:"/webconsole", port:port, service:"www" );

log_message( data:build_detection_report( app:"Sophos XG Firewall",
                                          version:version,
                                          install:"/webconsole",
                                          cpe:cpe,
                                          concluded:vers[0], concludedUrl:concUrl ),
             port:port );

exit( 0 );
