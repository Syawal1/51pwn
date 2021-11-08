###############################################################################
# OpenVAS Vulnerability Test
#
# Roundcube Webmail Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111027");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-08-21 16:00:00 +0200 (Fri, 21 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Roundcube Webmail Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server
  and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/roundcube", "/webmail", "/mail", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/", port:port );

  if( eregmatch( pattern:'<title>.*Roundcube Webmail.*</title>', string:buf, icase:TRUE ) ||
      ( "rcmloginuser" >< buf && "rcmloginpwd" >< buf ) || "new rcube_webmail();" >< buf ) {

    version = 'unknown';

    url = dir + "/CHANGELOG";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    ver = eregmatch( pattern:'RELEASE (([0-9.]+)(-([a-zA-Z]+))?)', string:buf );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    cpe = "cpe:/a:roundcube:webmail";
    if( version != "unknown" ) {
      if( !isnull( ver[3] ) )
        cpe = cpe + ":" + ver[2] + ":" + ver[4];
      else
        cpe = cpe + ":" + version;
    }

    set_kb_item( name:"www/" + port + "/roundcube", value:version );
    set_kb_item( name:"roundcube/detected", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Roundcube Webmail",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
