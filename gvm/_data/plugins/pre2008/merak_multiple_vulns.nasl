# OpenVAS Vulnerability Test
# Description: Multiple Vulnerabilities in Merak Webmail / IceWarp Web Mail
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
#

CPE = "cpe:/a:icewarp:mail_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14379");
  script_version("2020-11-05T10:18:37+0000");
  script_tag(name:"last_modification", value:"2020-11-05 10:18:37 +0000 (Thu, 05 Nov 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2004-1719", "CVE-2004-1720", "CVE-2004-1721", "CVE-2004-1722");
  script_bugtraq_id(10966);

  script_xref(name:"OSVDB", value:"9037");
  script_xref(name:"OSVDB", value:"9038");
  script_xref(name:"OSVDB", value:"9039");
  script_xref(name:"OSVDB", value:"9040");
  script_xref(name:"OSVDB", value:"9041");
  script_xref(name:"OSVDB", value:"9042");
  script_xref(name:"OSVDB", value:"9043");
  script_xref(name:"OSVDB", value:"9044");
  script_xref(name:"OSVDB", value:"9045");

  script_name("IceWarp Web Mail < 7.5.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_consolidation.nasl");
  script_mandatory_keys("icewarp/mailserver/http/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Merak Webmail / IceWarp Web Mail 7.5.2 or later.");

  script_tag(name:"summary", value:"IceWarp Web Mail is prone to multiple XSS, HTML and SQL injection,
  and PHP source code disclosure vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/inc/function.php";

if (http_vuln_check(port: port, url: url, pattern: "function getusersession", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
