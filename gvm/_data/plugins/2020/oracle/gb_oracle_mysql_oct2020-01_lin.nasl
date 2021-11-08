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

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108958");
  script_version("2020-10-30T09:58:42+0000");
  script_tag(name:"last_modification", value:"2020-10-30 09:58:42 +0000 (Fri, 30 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-23 09:17:56 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2020-14765", "CVE-2020-14769", "CVE-2020-14812", "CVE-2020-14793", "CVE-2020-14672",
                "CVE-2020-14867");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL < 5.6.50 / 5.7.x < 5.7.32 / 8.0.x < 8.0.22 Security Update (cpuoct2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL 5.6.49 and prior, 5.7.31 and prior, 8.0.21 and prior.");

  script_tag(name:"solution", value:"Update to version 5.6.50, 5.7.32, 8.0.22 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2020.html#AppendixMSQL");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.6.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.50", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "5.7", test_version2: "5.7.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
