###############################################################################
# OpenVAS Vulnerability Test
#
# BaconMap Local File Include and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100853");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-10-13 13:28:00 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-4800", "CVE-2010-4801");
  script_bugtraq_id(43908);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("BaconMap Local File Include and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43908");
  script_xref(name:"URL", value:"http://baconmap.nmsu.edu/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"BaconMap is prone to a local file-include vulnerability and an SQL-
injection vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit the local file-include vulnerability using directory-
traversal strings to view and execute arbitrary local files within the
context of the webserver process. Information harvested may aid in
further attacks.

The attacker can exploit the SQL-injection vulnerability to compromise
the application, access or modify data, exploit latent vulnerabilities
in the underlying database, or bypass the authentication control.

BaconMap 1.0 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/baconmap", "/map", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir,"/admin/updatelist.php?filepath=../includes/settings.php");

  if(http_vuln_check(port:port, url:url,pattern:"This file is the settings file for BaconMap",extra_check:make_list("\$database","\$password","\$dbhost"))) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
