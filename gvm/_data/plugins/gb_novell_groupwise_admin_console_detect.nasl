###############################################################################
# OpenVAS Vulnerability Test
#
# GroupWise Administration Console Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105077");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-09-03 15:08:39 +0200 (Wed, 03 Sep 2014)");
  script_name("GroupWise Administration Console Detection");

  script_tag(name:"summary", value:"The script sends a connection
request to the server and attempts to detect the GroupWise Administration Console.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9710);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:9710 );

url = "/gwadmin-console/login.jsp";
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req );
if(!buf) exit( 0 );

if( "<title>GroupWise Administration Console</title>" >< buf && "Novell, Inc" >< buf && "username_ui" >< buf )
{
  set_kb_item(name:"groupwise/admin_console/installed",value:TRUE);

  cpe = "cpe:/a:novell:groupwise";

  register_product( cpe:cpe, location:url, port:port, service:"www" );

  log_message( data: build_detection_report( app:"GroupWise Administration Console",
                                             version:'unknown',
                                             install:url,
                                             cpe:cpe,
                                             concluded: 'Remote probe' ),
               port:port );
}

exit( 0 );
