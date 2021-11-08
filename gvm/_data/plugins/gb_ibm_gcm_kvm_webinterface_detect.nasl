###############################################################################
# OpenVAS Vulnerability Test
#
# IBM GCM16 and GCM32 Global Console Managers Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105176");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-01-21 12:16:43 +0100 (Wed, 21 Jan 2015)");
  script_name("IBM GCM16 and GCM32 Global Console Managers iWebinterface Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to detect
  the IBM GCM16 and GCM32 Global Console Managers Webinterface from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

http_port = http_get_port( default:443 );

url = '/login.php';
req = http_get( item:url, port:http_port );
buf = http_send_recv( port:http_port, data:req, bodyonly:FALSE );

if( egrep( pattern:'<title>GCM(16|32) Explorer</title>', string:buf ) && ">User Login" >< buf ) {
  set_kb_item( name:"GCM_16_32/web/installed", value:TRUE);
  if( "GCM16" >< buf )
    cpe = 'cpe:/o:ibm:global_console_manager_16_firmware';
  else
    cpe = 'cpe:/o:ibm:global_console_manager_32_firmware';

  register_product( cpe:cpe, location:url, port:http_port, service:"www" );

  set_kb_item(name:"GCM_16_32/web/port", value:http_port );

  log_message( port:http_port );
}

exit( 0 );
