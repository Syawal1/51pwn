###############################################################################
# OpenVAS Vulnerability Test
#
# Apple TV Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105899");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-09-28 12:11:23 +0200 (Wed, 28 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apple TV Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 3689);
  script_mandatory_keys("iTunes/banner");

  script_tag(name:"summary", value:"This script performs http based detection of Apple TV devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");


include("host_details.inc");

port = http_get_port( default:3689 );

banner = http_get_remote_headers( port:3689, ignore_broken:TRUE );

if( ! banner || "DAAP-Server: iTunes/" >!< banner || "OS X" >!< banner ) exit( 0 );

set_kb_item( name:'apple_tv/detected', value:TRUE );
register_product( cpe:'cpe:/a:apple:apple_tv', location:"/", port:port, service:"www" );

register_and_report_os( os:"Apple TV", cpe:"cpe:/o:apple:tv", banner_type:"HTTP banner", port:port, desc:"Apple TV Detection", runs_key:"unixoide" );

log_message( port:port, data:"The remote host is an Apple TV device");
exit( 0 );

