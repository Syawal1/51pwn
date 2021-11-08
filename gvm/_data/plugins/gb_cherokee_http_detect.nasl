# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113692");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 12:00:00 +0200 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cherokee Web Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks whether Cherokee Web Server is present on
  the target system and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"https://cherokee-project.com/");

  exit(0);
}

CPE = "cpe:/a:cherokee-project:cherokee:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

buf = http_get_remote_headers( port: port );

# Server: Cherokee/0.2.7
# Server: Cherokee
# Server: Cherokee/0.99.39 (Gentoo Linux)
# Server: Cherokee/1.2.103 (Arch Linux)
if( buf =~ "Server\s*:\s*Cherokee" ) {
  set_kb_item( name: "cherokee/detected", value: TRUE );

  version = "unknown";

  vers = eregmatch( string: buf, pattern: "Server\s*:\s*Cherokee/([0-9.]+)", icase: TRUE );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  register_and_report_cpe( app: "Cherokee Web Server",
                           ver: version,
                           concluded: vers[0],
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www" );

  exit( 0 );
}

# nb: Proxies could prevent us from getting the desired banner information
#     But Cherokee's 404 page announces the installed version, so we can use that

vt_strings = get_vt_strings();

foreach dir( make_list_unique( "/", "/cherokee", http_cgi_dirs( port: port ) ) ) {

  location = dir;
  if( location == "/" )
    location = "";

  url = location + "/" + vt_strings["default_rand"];
  req = http_get_req( port: port, url: url );
  buf = http_keepalive_send_recv( data: req, port: port );

  # <p><hr>
  # Cherokee web server 1.2.101 (UNIX), Port 443
  # </body>
  if( buf =~ "Cherokee web server" ) {
    set_kb_item( name: "cherokee/detected", value: TRUE );

    version = "unknown";

    vers = eregmatch( string: buf, pattern: "Cherokee web server ([0-9.]+)", icase: TRUE );
    if( ! isnull( vers[1] ) )
      version = vers[1];

    register_and_report_cpe( app: "Cherokee Web Server",
                             ver: version,
                             concluded: vers[0],
                             base: CPE,
                             expr: "([0-9.]+)",
                             insloc: dir,
                             regPort: port,
                             regService: "www",
                             conclUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );

    exit( 0 );
  }
}

exit( 0 );
