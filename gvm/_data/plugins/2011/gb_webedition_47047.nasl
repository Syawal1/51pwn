###############################################################################
# OpenVAS Vulnerability Test
#
# webEdition CMS HTML Injection and Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103134");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-03-28 19:09:51 +0200 (Mon, 28 Mar 2011)");
  script_bugtraq_id(47047);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("webEdition CMS HTML Injection and Local File Include Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/47047");
  script_xref(name:"URL", value:"http://www.webedition.org/de/index.php");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"webEdition CMS is prone to multiple HTML-injection vulnerabilities and
a local file-include vulnerability.

Exploiting these issues could allow an attacker to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie-based authentication credentials, and
execute arbitrary local scripts in the context of the webserver
process. This may allow the attacker to compromise the application and
the computer. Other attacks are also possible.

webEdition CMS 6.1.0.2 is vulnerable. Other versions may also
be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

vt_strings = get_vt_strings();

foreach dir( make_list_unique( "/webedition", "/webEdition", "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, '/openBrowser.php?url="onload="alert(/', vt_strings["lowercase"], '/)');

  if(http_vuln_check(port:port, url:url, pattern:"alert\(/" + vt_strings["lowercase"] + "/\)", extra_check:"<title>webEdition", check_header:TRUE)) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
