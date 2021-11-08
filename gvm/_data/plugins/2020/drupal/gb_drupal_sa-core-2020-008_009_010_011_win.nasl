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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144588");
  script_version("2020-09-17T04:30:33+0000");
  script_tag(name:"last_modification", value:"2020-09-17 04:30:33 +0000 (Thu, 17 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-17 04:29:55 +0000 (Thu, 17 Sep 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-13667", "CVE-2020-13668", "CVE-2020-13669", "CVE-2020-13670");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 8.x, 9.x Multiple Vulnerabilities (SA-CORE-2020-008, SA-CORE-2020-009, SA-CORE-2020-010, SA-CORE-2020-011) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Access bypass (CVE-2020-13667)

  - Multiple XSS (CVE-2020-13668, CVE-2020-13669)

  - Information disclosure (CVE-2020-13670)");

  script_tag(name:"affected", value:"Drupal 8.8.x and prior, 8.9.x and 9.0.x.");

  script_tag(name:"solution", value:"Update to version 8.8.10, 8.9.6, 9.0.6 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2020-008");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2020-009");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2020-010");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2020-011");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.8.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.8.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.9", test_version2: "8.9.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
