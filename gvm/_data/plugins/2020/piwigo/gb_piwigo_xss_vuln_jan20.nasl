# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143509");
  script_version("2020-03-31T06:24:37+0000");
  script_tag(name:"last_modification", value:"2020-03-31 06:24:37 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-02-13 03:31:28 +0000 (Thu, 13 Feb 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2020-8089", "CVE-2020-9467");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo < 2.10.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Stored XSS via the Group Name Field to the group_list page

  - Stored XSS via the file parameter in /ws.php because of the pwg.images.setInfo function");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Piwigo version 2.10.1 and probably prior.");

  script_tag(name:"solution", value:"Update to version 2.10.2 or later.");

  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/1150");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/1168");

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

if (version_is_less(version: version, test_version: "2.10.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.10.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
