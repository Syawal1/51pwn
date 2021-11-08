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

CPE = "cpe:/a:apache:openmeetings";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144687");
  script_version("2020-10-02T07:46:35+0000");
  script_tag(name:"last_modification", value:"2020-10-02 07:46:35 +0000 (Fri, 02 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-01 03:15:02 +0000 (Thu, 01 Oct 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2018-1286");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache OpenMeetings 4.0.0 - 5.0.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_openmeetings_detect.nasl");
  script_mandatory_keys("Apache/Openmeetings/Installed");

  script_tag(name:"summary", value:"Apache OpenMeetings is prone to a denial of service vulnerability in the
  NetTest web service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache OpenMeetings version 4.0.0 - 5.0.0.");

  script_tag(name:"solution", value:"Update to version 5.0.1 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/re2aed827cd24ae73cbc320e5808020c8d12c7b687ee861b27d728bbc%40%3Cuser.openmeetings.apache.org%3E");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "5.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
