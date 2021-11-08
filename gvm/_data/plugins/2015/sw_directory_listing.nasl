###############################################################################
# OpenVAS Vulnerability Test
#
# Enabled Directory Listing Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.111074");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-12-26 15:00:00 +0100 (Sat, 26 Dec 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Enabled Directory Listing Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Periodic_Table_of_Vulnerabilities_-_Directory_Indexing");

  script_tag(name:"summary", value:"The script attempts to identify directories with an enabled directory listing.");

  script_tag(name:"vuldetect", value:"Check the detected directories if a directory listing is enabled.");

  script_tag(name:"impact", value:"Based on the information shown an attacker might be able to gather additional info about
  the structure of this application.");

  script_tag(name:"affected", value:"Webservers with an enabled directory listing.");

  script_tag(name:"solution", value:"If not needed disable the directory listing within the webservers config.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

found = FALSE;
foundList = make_list();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  dir_pattern = "<title>" + dir;

  buf = http_get_cache( item:dir + "/", port:port );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" ) continue;

  if( egrep( string:buf, pattern:"(Directory listing |Index )(for |of )", icase:TRUE ) ) {
    foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
    found = TRUE;
  }

  # Jetty dir listing
  if( "<TITLE>Directory: /" >< buf && "<H1>Directory: /" >< buf ) {
    foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
    found = TRUE;
  }

  if( dir != "" ) {
    if( egrep( string:buf, pattern:dir_pattern, icase:TRUE ) ) {
      foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
      found = TRUE;
    }
  }
}

if( found ) {

  report = 'The following directories with an enabled directory listing were identified:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  foundList = sort( foundList );

  foreach tmpFound( foundList ) {
    report += tmpFound + '\n';
  }

  report += '\nPlease review the content manually.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
