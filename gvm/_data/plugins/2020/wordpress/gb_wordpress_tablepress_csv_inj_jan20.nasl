# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions excerpted from a referenced source are
# Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112685");
  script_version("2020-08-06T13:39:56+0000");
  script_tag(name:"last_modification", value:"2020-08-06 13:39:56 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-01-13 10:52:00 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-20180");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress TablePress Plugin < 1.10 CSV Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/tablepress/detected");

  script_tag(name:"summary", value:"The WordPress plugin TablePress is prone to a CSV injection vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to force an unknown user to execute code on the affected device.");

  script_tag(name:"affected", value:"WordPress TablePress plugin before version 1.10.");

  script_tag(name:"solution", value:"Update to version 1.10 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/tablepress/#developers");
  script_xref(name:"URL", value:"https://medium.com/@Pablo0xSantiago/cve-2019-20180-tablepress-version-1-9-2-csv-injection-65309fcc8be8");

  exit(0);
}

CPE = "cpe:/a:tobias_baethge:tablepress";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less(version: version, test_version: "1.10" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
