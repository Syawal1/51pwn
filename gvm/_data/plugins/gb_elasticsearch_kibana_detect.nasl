###############################################################################
# OpenVAS Vulnerability Test
#
# Elasticsearch Kibana/X-Pack Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808087");
  script_version("2020-11-12T09:00:47+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-12 09:00:47 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2016-06-21 12:44:48 +0530 (Tue, 21 Jun 2016)");
  script_name("Elasticsearch Kibana/X-Pack Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5601);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Elasticsearch Kibana and X-Pack.

  This script sends an HTTP GET request and tries to ensure the presence of
  Elasticsearch Kibana and X-Pack from the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:5601 );

foreach dir( make_list_unique( "/", "/kibana", http_cgi_dirs( port:port ) ) ) {

  # nb: This dir might be already included in our http_cgi_dirs() from DDI_Directory_Scanner.nasl
  # which would cause a detection request like /app/kibana/app/kibana below. This is causing
  # a doubled detection because newer versions of Kibana are not answering with a 404 on non-existent
  # pages like /app/kibana/test anymore. Same happens for /app/ui/app/kibana as well.
  if( "/app/kibana" >< dir || "/app/ui" >< dir )
    continue;

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/app/kibana";
  res = http_get_cache( item:url, port:port );

  if( res =~ "^HTTP/1\.[01] 200" && ( egrep( string:res, pattern:"^kbn-(name|version|license-sig|xpack-sig): ", icase:TRUE ) || "<title>Kibana</title>" >< res || "x-app-name: kibana" >< res ) ) {

    version = "unknown";
    vers = eregmatch( pattern:"kbn-version: ([0-9.]+)", string:res );
    if( vers[1] )
      version = vers[1];

    if( version == "unknown" ) {
      # x-app-version: 4.3.0
      vers = eregmatch( pattern:"x-app-version: ([0-9.]+)", string:res );
      if( vers[1] )
        version = vers[1];
    }

    if( version == "unknown" ) {
      # "url":"/app/kibana"}],"version":"4.3.0","buildNum":9369,"buildSha":"
      # <kbn-injected-metadata data="{&quot;version&quot;:&quot;7.4.1&quot;,&quot;buildNumber&quot;:26479,&quot;branch&quot;:&quot;7.4&quot;,
      # false,&quot;tooltip&quot;:&quot;&quot;}],&quot;version&quot;:&quot;6.4.2&quot;,&quot;branch&quot;:&quot;6.4&quot;,&quot;buildNum&quot;:18010,&quot;buildSha&quot;:&quot;
      vers = eregmatch( pattern:'version(&quot;|"):(&quot;|")([0-9.]+)', string:res );
      if( vers[3] )
        version = vers[3];
    }

    set_kb_item( name:"Elasticsearch/Kibana/Installed", value:TRUE );
    register_and_report_cpe( app:"Elasticsearch Kibana", ver:version, base:"cpe:/a:elasticsearch:kibana:", expr:"^([0-9.]+)", concluded:vers[0], insloc:install, regPort:port, regService:"www" );
  }

  # nb: The X-Pack version is always matching the Kibana version
  # The redirect if X-Pack is installed looks like:
  # location: /login?next=%2Fkibana%2Fapp%2Fkibana
  # (note the lowercase of the location as well as the subdir from the dir loop above)
  if( res =~ "^HTTP/1\.[01] 302" && egrep( string:res, pattern:"^kbn-(name|version|license-sig|xpack-sig): ", icase:TRUE ) && res =~ "ocation: .*/login\?next=%2F.*app%2Fkibana" ) {

    version = "unknown";
    set_kb_item( name:"Elasticsearch/Kibana/Installed", value:TRUE );
    set_kb_item( name:"Elasticsearch/Kibana/X-Pack/Installed", value:TRUE );
    vers = eregmatch( pattern:"kbn-version: ([0-9.]+)", string:res );
    if( vers[1] )
      version = vers[1];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:elasticsearch:kibana:" );
    if( ! cpe )
      cpe = "cpe:/a:elasticsearch:kibana";
    register_product( cpe:cpe, location:install, port:port, service:"www" );

    report = build_detection_report( app:"Elasticsearch Kibana",
                                     version:version,
                                     install:install,
                                     cpe:cpe,
                                     concluded:vers[0] );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:elasticsearch:x-pack:" );
    if( ! cpe )
      cpe = "cpe:/a:elasticsearch:x-pack";
    register_product( cpe:cpe, location:install, port:port, service:"www" );

    report += '\n\n';
    report += build_detection_report( app:"Elasticsearch Kibana X-Pack",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:vers[0],
                                      extra:"Note: The X-Pack version is always matching the Kibana version" );
    log_message( port:port, data:report );
    exit( 0 ); # We only want to report the X-Pack once as it would report the 302 redirect for each called subdir
  }

  if( res =~ "^HTTP/1\.[01] 503" && concl = egrep( string:res, pattern:"^Kibana server is not ready yet", icase:FALSE ) ) {
    set_kb_item( name:"Elasticsearch/Kibana/Installed", value:TRUE );
    register_and_report_cpe( app:"Elasticsearch Kibana", ver:"unknown", cpename:"cpe:/a:elasticsearch:kibana", concluded:'HTTP/1.1 503\n(truncated)\n' + chomp( concl ), insloc:install, regPort:port, regService:"www" );
    exit( 0 ); # Similar for X-Pack above
  }
}

exit( 0 );
