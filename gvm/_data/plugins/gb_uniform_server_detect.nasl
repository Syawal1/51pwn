###############################################################################
# OpenVAS Vulnerability Test
#
# Uniform Server Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800786");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Uniform Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed Uniform Server version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

uniPort = http_get_port(default:80);

res = http_get_cache(item:"/", port:uniPort);

if( ">Uniform Server" >< res ) {

  version = "unknown";
  install = "/";

  ver = eregmatch( pattern:"Uniform Server (([0-9.]+).?([a-zA-Z]+))", string:res );
  if( ver[1] != NULL ) version = ver[1];

  set_kb_item( name:"www/" + uniPort + "/Uniform-Server", value:version );
  set_kb_item( name:"uniform-server/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:uniformserver:uniformserver:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:uniformserver:uniformserver';

  register_product( cpe:cpe, location:install, port:uniPort, service:"www" );

  log_message( data:build_detection_report( app:"Uniform Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:uniPort );
}

exit( 0 );
