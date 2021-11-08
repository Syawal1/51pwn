###############################################################################
# OpenVAS Vulnerability Test
#
# Sambar default CGI info disclosure
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2008 Renaud Deraison
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
  script_oid("1.3.6.1.4.1.25623.1.0.80082");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_bugtraq_id(7207, 7208);
  script_cve_id("CVE-2003-1284");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Sambar default CGI info disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Renaud Deraison");
  script_family("Web application abuses");
  script_dependencies("gb_sambar_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sambar_server/detected");

  script_tag(name:"solution", value:"Delete these two CGIs");

  script_tag(name:"summary", value:"The remote web server is running two CGIs (environ.pl and
  testcgi.exe) which, by default, disclose a lot of information
  about the remote host (such as the physical path to the CGIs on
  the remote filesystem).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/cgi-bin/testcgi.exe";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "SCRIPT_FILENAME" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

url = "/cgi-bin/environ.pl";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "DOCUMENT_ROOT" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
