###############################################################################
# OpenVAS Vulnerability Test
#
# CodeThatShoppingCart Input Validation Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.18255");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1593", "CVE-2005-1594", "CVE-2005-1595");
  script_bugtraq_id(13560);
  script_xref(name:"OSVDB", value:"16155");
  script_xref(name:"OSVDB", value:"16156");
  script_xref(name:"OSVDB", value:"16157");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CodeThatShoppingCart Input Validation Vulnerabilities");
  script_family("Web application abuses");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote version of CodeThat.com ShoppingCart contains an
  input validation flaw leading to a SQL injection vulnerability.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to execute
  arbitrary commands against the remote database.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/catalog.php?action=category_show&id='";

  if( http_vuln_check( port:port, url:url, pattern:"select id from products P, category_products CP where P\.id=CP\.product_id and CP\.category_id=" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
