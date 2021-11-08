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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144074");
  script_version("2020-06-05T09:44:25+0000");
  script_tag(name:"last_modification", value:"2020-06-05 09:44:25 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 09:29:45 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2020-13761", "CVE-2020-13762");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 3.0.0 - 3.9.18 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Joomla! is prone to multiple cross-site scripting vulnerabilities:

  - XSS in modules heading tag option (CVE-2020-13761)

  - XSS in com_modules tag options (CVE-2020-13762)");

  script_tag(name:"affected", value:"Joomla! versions 3.0.0 - 3.9.18.");

  script_tag(name:"solution", value:"Update to version 3.9.19 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/813-20200601-core-xss-in-modules-heading-tag-option");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/815-20200603-core-xss-in-com-modules-tag-options");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.9.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.19", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
