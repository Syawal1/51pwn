# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140160");
  script_version("2019-06-07T05:46:04+0000");
  script_tag(name:"last_modification", value:"2019-06-07 05:46:04 +0000 (Fri, 07 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-07 05:38:14 +0000 (Fri, 07 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2019-9753");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 7.0.x < 7.0.5 Information Disclosure Vulnerability (OSA-2019-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker who is logged into OTRS as an agent or a customer user can use the
  search result screens to disclose information from invalid system entities.");

  script_tag(name:"affected", value:"OTRS 7.0.x prior to version 7.0.5.");

  script_tag(name:"solution", value:"Update to version 7.0.5 or later.");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2019-03-security-update-for-otrs-framework/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
