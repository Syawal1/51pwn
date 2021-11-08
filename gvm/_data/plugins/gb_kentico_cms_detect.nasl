###############################################################################
# OpenVAS Vulnerability Test
#
# Kentico CMS Product Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113117");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-20 13:31:37 +0100 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kentico CMS Product Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Product detection for Kentico CMS.");

  script_xref(name:"URL", value:"https://www.kentico.com");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

http_port = http_get_port( default: 80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: http_port ) ) ) {

  res = http_get_cache( port: http_port, item: dir );
  if( '<meta name="generator" content="Kentico' >< res ) {

    vers = "unknown";

    version = eregmatch( string: res, pattern: 'content="Kentico [CMS ]{0,4}[0-9.(betaR)?]+ \\(build ([0-9.]+)\\)', icase: TRUE );

    if( ! isnull( version[1] ) ) {
      vers = version[1];
    }

    set_kb_item( name: "kentico_cms/detected", value: TRUE );

    register_and_report_cpe( app: "Kentico CMS",
                             ver: version[1],
                             concluded: version[0],
                             base: "cpe:/a:kentico:cms:",
                             expr: "([0-9.]+)",
                             insloc: dir,
                             conclUrl: dir,
                             regPort: http_port );
  }
}

exit( 0 );
