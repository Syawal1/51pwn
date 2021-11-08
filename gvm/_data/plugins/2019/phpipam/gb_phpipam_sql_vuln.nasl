# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142936");
  script_version("2020-09-28T14:05:41+0000");
  script_tag(name:"last_modification", value:"2020-09-28 14:05:41 +0000 (Mon, 28 Sep 2020)");
  script_tag(name:"creation_date", value:"2019-09-25 10:09:35 +0000 (Wed, 25 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-16692", "CVE-2019-16693", "CVE-2019-16694", "CVE-2019-16695", "CVE-2019-16696",
                "CVE-2020-7988");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpIPAM <= 1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("phpipam/installed");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"phpIPAM is prone to multiple vulnerabilities:

  - Multiple SQL injection vulnerabilities (CVE-2019-16692, CVE-2019-16693, CVE-2019-16694, CVE-2019-16695,
    CVE-2019-16696)

  - CSRF vulnerability");

  script_tag(name:"affected", value:"phpIPAM version 1.4 and prior.");

  script_tag(name:"solution", value:"Update to the latest version of phpIPAM.");

  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/2738");
  script_xref(name:"URL", value:"https://pastebin.com/ZPECbgZb");

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

if (version_is_less_equal(version: version, test_version: "1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Update to the latest version", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
