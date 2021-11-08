###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Bookly Plugin XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112220");
  script_version("2020-11-10T11:45:08+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2018-02-13 08:46:00 +0100 (Tue, 13 Feb 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-6891");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Bookly Plugin XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/bookly-responsive-appointment-booking-tool/detected");

  script_tag(name:"summary", value:"Bookly plugin for WordPress is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Bookly plugin before version 14.5.");

  script_tag(name:"solution", value:"Update to version 14.5 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/bookly-responsive-appointment-booking-tool/#developers");
  script_xref(name:"URL", value:"https://www.gubello.me/blog/bookly-blind-stored-xss/");

  exit(0);
}

CPE = "cpe:/a:bookly:bookly-responsive-appointment-booking-tool";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "14.5" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
