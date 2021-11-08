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
  script_oid("1.3.6.1.4.1.25623.1.0.108966");
  script_version("2020-10-30T09:58:42+0000");
  script_tag(name:"last_modification", value:"2020-10-30 09:58:42 +0000 (Fri, 30 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-23 09:17:56 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2020-14878", "CVE-2020-14828", "CVE-2020-14830", "CVE-2020-14836", "CVE-2020-14846",
                "CVE-2020-14800", "CVE-2020-14821", "CVE-2020-14829", "CVE-2020-14848", "CVE-2020-14852",
                "CVE-2020-14814", "CVE-2020-14804", "CVE-2020-14773", "CVE-2020-14777", "CVE-2020-14785",
                "CVE-2020-14794", "CVE-2020-14809", "CVE-2020-14837", "CVE-2020-14839", "CVE-2020-14845",
                "CVE-2020-14861", "CVE-2020-14866", "CVE-2020-14868", "CVE-2020-14888", "CVE-2020-14891",
                "CVE-2020-14893", "CVE-2020-14786", "CVE-2020-14844", "CVE-2020-14870", "CVE-2020-14873",
                "CVE-2020-14838", "CVE-2020-14860", "CVE-2020-14791");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL < 8.0.22 Security Update (cpuoct2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL 8.0.21 and prior.");

  script_tag(name:"solution", value:"Update to version 8.0.22 or later.");

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

if (version_is_less(version: version, test_version: "8.0.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
