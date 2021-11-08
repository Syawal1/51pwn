###############################################################################
# OpenVAS Vulnerability Test
#
# Cacti Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100204");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-05-16 14:32:16 +0200 (Sat, 16 May 2009)");
  script_name("Cacti Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Cacti.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/cacti", "/monitoring", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( buf == NULL ) continue;

  if( egrep( pattern:'Login to Cacti', string:buf, icase:TRUE ) &&
      egrep( pattern:"Set-Cookie: Cacti", string:buf ) ) {

    vers = "unknown";

    version = eregmatch( pattern:"versionInfo'>Version ([0-9.]+[a-z]{0,1})", string:buf );
    if( ! isnull( version[1] ) ) vers = version[1];

    if( vers == "unknown" ) {

      url = dir + "/docs/CHANGELOG";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      if( "Cacti CHANGELOG" >< buf && "-bug#" >< buf ) {
        version = eregmatch( string:buf, pattern:"([0-9.]+[a-z]{0,1})", icase:TRUE );
        if( ! isnull( version[1] ) ) {
          vers = version[1];
          concurl = http_report_vuln_url( url:url, port:port, url_only:TRUE );
        }
      }
    }

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/cacti", value:tmp_version );
    set_kb_item( name:"cacti/installed", value:TRUE );

    cpe = build_cpe( value:tmp_version, exp:"([0-9.]+[a-z]{0,1})", base:"cpe:/a:cacti:cacti:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:cacti:cacti";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Cacti",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0],
                                              concludedUrl:concurl ),
                                              port:port );
    exit( 0 ); # nb: Do avoid duplicated detections with from the "Set-Cookie" above
  }
}

exit( 0 );
