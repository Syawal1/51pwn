###############################################################################
# OpenVAS Vulnerability Test
#
# Tableau Server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111048");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-11-09 12:00:00 +0100 (Mon, 09 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Tableau Server Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP
  request to the server and attempts to identify a Tableau Server
  and its version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

if( concluded = eregmatch( string: banner, pattern: "Server: Tableau", icase:TRUE ) ) {
  installed = TRUE;
  concl = concluded[0];
  version = "unknown";
}

res = http_get_cache( item:"/", port:port );

if( concluded = eregmatch( string: res, pattern: 'VizPortal.BuildId|vizportal-config" data-buildId' ) ) {
  installed = TRUE;
  concl = concluded[0];
  version = "unknown";
}

res = http_get_cache( item:"/auth", port:port );

if( concluded = eregmatch( string: res, pattern: ">Version&nbsp;([0-9.]+)" ) ) {
  installed = TRUE;
  concl = concluded[0];
  version = concluded[1];
} else {
  req = http_get_req(port: port, url: "/api/3.0/serverinfo");
  res = http_keepalive_send_recv(port: port, data: req);

  #<productVersion build="20181.18.0706.1237">2018.1.3</productVersion>
  concluded = eregmatch(pattern: ">([^<]+)</productVersion>", string: res);
  if(!isnull(concluded)) {
    concl = concluded[0];
    version = concluded[1];
  }
}

if( installed ) {

  set_kb_item( name:"www/" + port + "/tableau_server", value:version );
  set_kb_item( name:"tableau_server/installed", value:TRUE );

  cpe = build_cpe( value: version, exp:"^([0-9.]+)",base:"cpe:/a:tableausoftware:tableau_server:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:tableausoftware:tableau_server';

  register_product( cpe:cpe, location:port + '/tcp', port:port, service:"www" );

  log_message( data:build_detection_report( app:"Tableau Server",
                                            version:version,
                                            install:port + '/tcp',
                                            cpe:cpe,
                                            concluded:concl ),
                                            port:port );
}

exit(0);
