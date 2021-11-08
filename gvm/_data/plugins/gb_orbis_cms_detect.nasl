###############################################################################
# OpenVAS Vulnerability Test
#
# Orbis CMS Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.801403");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_name("Orbis CMS Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the running Orbis CMS version.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

orbisPort = http_get_port(default:80);

if( !http_can_host_php( port:orbisPort ) ) exit( 0 );

foreach path (make_list_unique("/orbis", "/Orbis", "/", http_cgi_dirs(port:orbisPort)))
{

  install = path;
  if( path == "/" ) path = "";

  sndReq = http_get(item: path + "/admin/login.php", port:orbisPort);
  rcvRes = http_keepalive_send_recv(port:orbisPort, data:sndReq);

  if(">Powered by Orbis CMS<" >< rcvRes)
  {
    sndReq = http_get(item: path + "/CHANGELOG.txt", port:orbisPort);
    rcvRes = http_keepalive_send_recv(port:orbisPort, data:sndReq);

    version = "unknown";

    orbisVer = eregmatch(pattern:"Version ([0-9.]+)", string:rcvRes);

    if(orbisVer[1] != NULL) version = orbisVer[1];

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + orbisPort + "/Orbis/CMS/Ver", value:tmp_version);
    set_kb_item(name:"orbis/cms/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:novo-ws:orbis_cms:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:novo-ws:orbis_cms';

    register_product( cpe:cpe, location:install, port:orbisPort, service:"www" );

    log_message( data: build_detection_report( app:"Orbis CMS",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded: orbisVer[0]),
                                               port:orbisPort);

  }
}
