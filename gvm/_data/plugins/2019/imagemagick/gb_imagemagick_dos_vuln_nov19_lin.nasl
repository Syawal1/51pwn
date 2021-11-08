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
  script_oid("1.3.6.1.4.1.25623.1.0.113564");
  script_version("2019-11-14T10:41:32+0000");
  script_tag(name:"last_modification", value:"2019-11-14 10:41:32 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-14 11:32:42 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-18853");

  script_name("ImageMagick < 7.0.9-0 Denial of Service (DoS) Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_imagemagick_detect_lin.nasl");
  script_mandatory_keys("ImageMagick/Lin/Ver");

  script_tag(name:"summary", value:"ImageMagick is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists because
  XML_PARSE_HUGE is not properly restricted in coders/svg.c.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to exhaust
  the target system's resources.");
  script_tag(name:"affected", value:"ImageMagick through version 7.0.8-68.");
  script_tag(name:"solution", value:"Update to version 7.0.9-0 or later.");

  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-19-136");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/ec9c8944af2bfc65c697ca44f93a727a99b405f1");

  exit(0);
}

CPE = "cpe:/a:imagemagick:imagemagick";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.0.9.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.9-0", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
