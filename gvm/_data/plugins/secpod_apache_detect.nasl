###############################################################################
# OpenVAS Vulnerability Test
#
# Apache HTTP/Web Server Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900498");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache HTTP/Web Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_get_http_banner.nasl", "apache_server_info.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("apache_or_server-info/banner");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks whether Apache HTTP/Web Server is present
  on the target system.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

# Just the default server banner without catching e.g. Apache-Tomcat
if( banner && "Apache" >< banner && "Apache-" >!< banner ) {

  version = "unknown";
  installed = TRUE;

  vers = eregmatch( pattern:"Server:.*Apache/([0-9.]+(-(alpha|beta))?)", string:banner );
  if( ! isnull( vers[1] ) )
    version = vers[1];
}

if( ! version || version == "unknown" ) {

  # From apache_server_info.nasl
  server_info = get_kb_item( "www/server-info/banner/" + port );
  if( server_info ) {

    url = "/server-info";
    version = "unknown";
    installed = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"Server: .*(Rapidsite/Apa|Apache)/([0-9.]+(-(alpha|beta))?)", string:server_info );
    if( ! isnull( vers[2] ) ) {
      version = vers[2];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: " + vers[1] + "/" + version );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: " + vers[1] );
    }
  }
}

if( ! version || version == "unknown" ) {

  url = "/non-existent.html";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE, fetch404:TRUE );

  # If banner is changed by e.g. mod_security but default error page still exists
  if( res =~ "^HTTP/1\.[01] [3-5].*" && res =~ "<address>.* Server at .* Port.*</address>" ) {

    version = "unknown";
    installed = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"<address>Apache/([0-9.]+(-(alpha|beta))?).* Server at .* Port ([0-9.]+)</address>", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache/" + version );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache" );
    }
  }
}

if( ! version || version == "unknown" ) {

  url = "/manual/en/index.html";
  res = http_get_cache( item:url, port:port );

  # From the apache docs, this is only providing the major release (e.g. 2.4)
  if( res =~ "^HTTP/1\.[01] 200" && "<title>Apache HTTP Server Version" >< res && "Documentation - Apache HTTP Server" >< res ) {

    version = "unknown";
    installed = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"<title>Apache HTTP Server Version ([0-9]\.[0-9]+).*Documentation - Apache HTTP Server.*</title>", string:res );

    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache/" + version );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache" );
    }
  }
}

if( installed ) {

  install = port + "/tcp";

  set_kb_item( name:"www/" + port + "/Apache", value:version );
  set_kb_item( name:"apache/installed", value:TRUE );

  baseCPE = "cpe:/a:apache:http_server";
  if( version != "unknown" ) {
    cpeVer = str_replace( string:version, find:"-", replace:":" );
    cpe = baseCPE + ":" + cpeVer;
  } else {
    cpe = baseCPE;
  }

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  log_message( data:build_detection_report( app:"Apache HTTP/Web Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );
