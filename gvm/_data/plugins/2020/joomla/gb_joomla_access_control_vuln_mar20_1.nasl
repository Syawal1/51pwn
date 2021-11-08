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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143603");
  script_version("2020-03-24T07:28:25+0000");
  script_tag(name:"last_modification", value:"2020-03-24 07:28:25 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-17 08:36:20 +0000 (Tue, 17 Mar 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-10238");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 2.5.0 - 3.9.15 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to an access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Various actions in com_templates lack the required ACL checks, leading to
  various potential attack vectors.");

  script_tag(name:"affected", value:"Joomla! versions 2.5.0 - 3.9.15.");

  script_tag(name:"solution", value:"Update to version 3.9.16 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/804-20200303-core-incorrect-access-control-in-com-templates");

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

if (version_in_range(version: version, test_version: "2.5.0", test_version2: "3.9.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.16", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
