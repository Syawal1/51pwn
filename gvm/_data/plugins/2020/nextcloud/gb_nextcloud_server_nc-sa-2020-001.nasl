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

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143455");
  script_version("2020-02-14T10:42:06+0000");
  script_tag(name:"last_modification", value:"2020-02-14 10:42:06 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-05 07:20:16 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"cvss_base", value:"3.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2019-15612");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 13.0.11, < 14.0.7, < 15.0.3 2FA Sessions Vulnerability (NC-SA-2020-001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a vulnerability where 2FA sessions are not
  properly expired on a password change.");

  script_tag(name:"insight", value:"A bug in Nextcloud Server causes pending 2FA logins to not be correctly
  expired when the password of the user is reset.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Nextcloud server versions prior 13.0.11, prior 14.0.7 and prior 15.0.3.");

  script_tag(name:"solution", value:"Update to version 13.0.11, 14.0.7, 15.0.3 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2020-001");

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

if (version_is_less(version: version, test_version: "13.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14.0.0", test_version2: "14.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "15.0.0", test_version2: "15.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
