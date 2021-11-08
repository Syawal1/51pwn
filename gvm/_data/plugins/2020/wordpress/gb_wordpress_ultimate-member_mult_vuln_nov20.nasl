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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117034");
  script_version("2020-11-11T10:57:50+0000");
  script_tag(name:"last_modification", value:"2020-11-11 10:57:50 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-10 10:48:54 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"Third Party");
  script_tag(name:"severity_date", value:"2020-11-09 00:00:00 +0000 (Mon, 09 Nov 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ultimate Member Plugin <= 2.1.11 Multiple Privilege Escalation Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ultimate-member/detected");

  script_tag(name:"summary", value:"The WordPress plugin Ultimate Member is prone to multiple
  critical privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - unauthenticated privilege escalation via User Meta

  - unauthenticated privilege escalation via User Roles

  - authenticated privilege escalation via Profile Update");

  script_tag(name:"impact", value:"Successful exploitation would allow originally unauthenticated users
  to escalate their privileges with some conditions. Once an attacker has elevated access to a WordPress
  site, they can potentially take over the entire and further infect the site with malware.");

  script_tag(name:"affected", value:"WordPress Ultimate Member plugin through version 2.1.11.");

  script_tag(name:"solution", value:"Update to version 2.1.12 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/ultimate-member/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/11/critical-privilege-escalation-vulnerabilities-affect-100k-sites-using-ultimate-member-plugin/");

  exit(0);
}

CPE = "cpe:/a:ultimatemember:ultimate-member";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "2.1.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.12", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
