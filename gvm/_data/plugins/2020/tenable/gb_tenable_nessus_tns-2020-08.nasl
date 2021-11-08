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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144901");
  script_version("2020-11-19T10:53:01+0000");
  script_tag(name:"last_modification", value:"2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-09 03:00:36 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-5793");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus 8.9.0 - 8.12.0 Vulnerability on Windows (TNS-2020-08)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nessus/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Tenable Nessus on Windows is prone to a vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in Nessus on Windows could allow an authenticated local
  attacker to copy user-supplied files to a specially constructed path in a specifically named user directory.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by creating a malicious file and
  copying the file to a system directory. The attacker needs valid credentials on the Windows system to exploit
  this vulnerability.");

  script_tag(name:"affected", value:"Tenable Nessus version 8.9.0 - 8.12.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 8.12.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2020-08");

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

if (version_in_range(version: version, test_version: "8.9.0", test_version2: "8.12.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.12.1", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
