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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143642");
  script_version("2020-04-02T06:08:29+0000");
  script_tag(name:"last_modification", value:"2020-04-02 06:08:29 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-26 04:10:34 +0000 (Thu, 26 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-2160", "CVE-2020-2161", "CVE-2020-2162", "CVE-2020-2163");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.228, < 2.204.6 LTS Multiple vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to multiple vulnerabilities:

  - CSRF protection for any URL could be bypassed (CVE-2020-2160)

  - Stored XSS vulnerability in label expression validation (CVE-2020-2161)

  - Stored XSS vulnerability in file parameters (CVE-2020-2162)

  - Stored XSS vulnerability in list view column headers (CVE-2020-2163)");

  script_tag(name:"affected", value:"Jenkins version 2.227 and prior and 2.204.5 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.228, 2.204.6 LTS or later.");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2020-03-25/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port))
  exit(0);

if (!version = infos["version"])
  exit(0);

location = infos["location"];
proto = infos["proto"];

if (get_kb_item("jenkins/" + port + "/is_lts")) {
  if (version_is_less(version: version, test_version: "2.204.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.204.6", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "2.228")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.228", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
