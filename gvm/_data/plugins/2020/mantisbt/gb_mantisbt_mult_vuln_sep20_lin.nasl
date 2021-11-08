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

CPE = "cpe:/a:mantisbt:mantisbt";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144699");
  script_version("2020-10-16T08:56:40+0000");
  script_tag(name:"last_modification", value:"2020-10-16 08:56:40 +0000 (Fri, 16 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-02 08:20:14 +0000 (Fri, 02 Oct 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2020-25781", "CVE-2020-25830", "CVE-2020-25288");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MantisBT < 2.24.3 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MantisBT is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Access to private bug note attachments (CVE-2020-25781)

  - HTML injection in bug_actiongroup_page.php (CVE-2020-25830)

  - HTML injection on bug_update_page.php (CVE-2020-25288)");

  script_tag(name:"affected", value:"MantisBT versions 2.24.2 and prior.");

  script_tag(name:"solution", value:"Update to version 2.24.3 or later.");

  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=27039");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=27304");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=27275");

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

if (version_is_less(version: version, test_version: "2.24.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.24.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
