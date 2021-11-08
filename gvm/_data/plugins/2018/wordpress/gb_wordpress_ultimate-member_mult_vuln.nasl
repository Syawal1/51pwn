###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Ultimate Member Plugin < 2.0.4 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.112283");
  script_version("2020-11-10T11:45:08+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2018-05-15 12:10:00 +0200 (Tue, 15 May 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2018-0585", "CVE-2018-0586", "CVE-2018-0587", "CVE-2018-0588", "CVE-2018-0589", "CVE-2018-0590");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ultimate Member Plugin < 2.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ultimate-member/detected");

  script_tag(name:"summary", value:"Ultimate Member plugin for WordPress is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Ultimate Member plugin before version 2.0.4.");
  script_tag(name:"impact", value:"- An arbitrary script may be executed on the user's web browser - CVE-2018-0585

  - Arbitrary local files on the server may be accessed by a logged-in user - CVE-2018-0586

  - An arbitrary image file can be uploaded by a remote attacker, which may be used for unauthorized file sharing - CVE-2018-0587

  - A remote attacker may delete arbitrary files on the server - CVE-2018-0588

  - A user with the Author role may add a new form - CVE-2018-0589

  - Profiles for other users may be modified by a logged-in user - CVE-2018-0590.");

  script_tag(name:"solution", value:"Update to version 2.0.4 or later.");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN28804532/index.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/ultimate-member/#developers");

  exit(0);
}

CPE = "cpe:/a:ultimatemember:ultimate-member";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "2.0.4" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
