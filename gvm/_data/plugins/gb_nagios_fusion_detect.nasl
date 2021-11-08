###############################################################################
# OpenVAS Vulnerability Test
#
# Nagios Fusion Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
#This program is free software; you can redistribute it and/or modify
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
  script_oid("1.3.6.1.4.1.25623.1.0.813251");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-06-18 13:05:09 +0530 (Mon, 18 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Nagios Fusion Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Nagios
  Fusion.

  The script sends a connection request to the server and attempts to extract
  the version number from the reply.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
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

foreach dir( make_list_unique( "/", "/Nagios", "/nagiosfusion", "/fusion", http_cgi_dirs( port:port ) ) )
{

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/login.php", port:port );
  if(rcvRes =~ ">Login.*Nagios Fusion</title" && '"product" value="nagiosfusion">' >< rcvRes)
  {

    version = "unknown";
    set_kb_item(name:"NagiosFusion/installed", value:TRUE);
    ver = eregmatch(pattern:'name="version" value="([0-9.]+)',string:rcvRes);
    if( ! isnull(ver[1] ) ){
     version = ver[1];
    }

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + port + "/NagiosFusion", value:tmp_version);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:nagiosfusion:nagiosfusion:");
    if(isnull(cpe))
      cpe = 'cpe:/a:nagiosfusion:nagiosfusion';

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data: build_detection_report( app:"Nagios Fusion",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:version),
                                               port:port );
  }
}

exit( 0 );
