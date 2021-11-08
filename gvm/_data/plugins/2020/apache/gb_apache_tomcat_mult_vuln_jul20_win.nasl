# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144274");
  script_version("2020-07-21T08:11:15+0000");
  script_tag(name:"last_modification", value:"2020-07-21 08:11:15 +0000 (Tue, 21 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-17 06:15:35 +0000 (Fri, 17 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-13934", "CVE-2020-13935");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Multiple DoS Vulnerabilities - July20 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilitities exist:

  - HTTP/2 Denial of Service (CVE-2020-13934)

  - WebSocket Denial of Service (CVE-2020-13935)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 8.5.1 to 8.5.56, 9.0.0.M5 to 9.0.36 and 10.0.0-M1 to 10.0.0-M6.");

  script_tag(name:"solution", value:"Update to version 8.5.57, 9.0.37, 10.0.0-M7 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r61f411cf82488d6ec213063fc15feeeb88e31b0ca9c29652ee4f962e%40%3Cannounce.tomcat.apache.org%3E");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/rd48c72bd3255bda87564d4da3791517c074d94f8a701f93b85752651%40%3Cannounce.tomcat.apache.org%3E");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.0-M7");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.37");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.57");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.56")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.57", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M5") >= 0) && (revcomp(a: version, b: "9.0.36") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.0.0.M1") >= 0) && (revcomp(a: version, b: "10.0.0.M6") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.0-M7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
