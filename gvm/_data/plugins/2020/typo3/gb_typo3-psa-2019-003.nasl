# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143430");
  script_version("2020-02-03T08:05:42+0000");
  script_tag(name:"last_modification", value:"2020-02-03 08:05:42 +0000 (Mon, 03 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-01-30 08:20:30 +0000 (Thu, 30 Jan 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2020-8091");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 XSS Vulnerability (TYPO3-PSA-2019-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"svg.swf in TYPO3 could allow an unauthenticated, remote attacker to conduct a
  cross-site scripting (XSS) attack on a targeted system. This may be at a contrib/websvg/svg.swf pathname.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.0 to 6.2.38 ELTS and 7.0.0 to 7.1.0.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-psa-2019-003/");

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

if (version_in_range(version: version, test_version: "6.2.0", test_version2: "6.2.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
