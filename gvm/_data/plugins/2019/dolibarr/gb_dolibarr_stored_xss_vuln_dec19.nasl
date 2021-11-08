# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113618");
  script_version("2019-12-09T12:50:46+0000");
  script_tag(name:"last_modification", value:"2019-12-09 12:50:46 +0000 (Mon, 09 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-09 13:44:42 +0000 (Mon, 09 Dec 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-19206");

  script_name("Dolibarr <= 10.0.3 Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to a stored cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is exploitable by a user when
  uploading a specially crafted SVG image as a profile picture.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to inject arbitrary HTML and JavaScript into the site.");
  script_tag(name:"affected", value:"Dolibarr through version 10.0.3.");
  script_tag(name:"solution", value:"Update to version 10.0.4.");

  script_xref(name:"URL", value:"https://medium.com/@k43p/cve-2019-19206-stored-xss-due-to-javascript-execution-in-an-svg-file-ee1d038fba76");

  exit(0);
}

CPE = "cpe:/a:dolibarr:dolibarr";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "10.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );