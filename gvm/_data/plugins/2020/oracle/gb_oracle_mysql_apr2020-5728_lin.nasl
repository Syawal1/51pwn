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
  script_oid("1.3.6.1.4.1.25623.1.0.143726");
  script_version("2020-07-22T06:26:30+0000");
  script_tag(name:"last_modification", value:"2020-07-22 06:26:30 +0000 (Wed, 22 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-20 03:11:53 +0000 (Mon, 20 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-5482", "CVE-2020-2790", "CVE-2020-2806", "CVE-2020-2814", "CVE-2019-5481");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL 5.7.x < 5.7.29 Security Update (cpuapr2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL versions 5.7.0 - 5.7.28.");

  script_tag(name:"solution", value:"Update to version 5.7.29 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixMSQL");

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

if (version_in_range(version: version, test_version: "5.7", test_version2: "5.7.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
