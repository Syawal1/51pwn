# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112587");
  script_version("2020-11-10T11:45:08+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-05-22 14:35:00 +0200 (Wed, 22 May 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-12239");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Booking System Plugin < 1.5.2 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-booking-system/detected");

  script_tag(name:"summary", value:"The WordPress plugin WP Booking System is prone to a CSRF vulnerability
  with the possible result of SQL injection.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to craft a malicious webpage that
  once visited by an authenticated administrative user, will trigger the SQL injection vulnerability.");
  script_tag(name:"affected", value:"WordPress WP Booking System plugin before version 1.5.2.");
  script_tag(name:"solution", value:"Update to version 1.5.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-booking-system/#developers");
  script_xref(name:"URL", value:"http://dumpco.re/bugs/wp-plugin-wp-booking-system-sqli");

  exit(0);
}

CPE = "cpe:/a:veribo:wp-booking-system";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.5.2" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
