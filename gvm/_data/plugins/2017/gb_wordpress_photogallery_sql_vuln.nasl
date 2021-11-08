###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Photo Gallery Plugin SQL Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112029");
  script_version("2020-11-10T11:45:08+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-08-25 10:34:31 +0200 (Fri, 25 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-12977");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Photo Gallery Plugin SQL Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/photo-gallery/detected");

  script_tag(name:"summary", value:"WordPress plugin Photo Gallery by Web-Dorado has a SQL injection vulnerability related to bwg_edit_tag() in photo-gallery.php and edit_tag() in admin/controllers/BWGControllerTags_bwg.php. It is exploitable by administrators via the tag_id parameter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Web-Dorado 'Photo Gallery by WD - Responsive Photo Gallery' plugin before 1.3.51.");

  script_tag(name:"solution", value:"Update to version 1.3.51 or later.");

  script_xref(name:"URL", value:"https://github.com/jgj212/Advisories/blob/master/photo-gallery.1.3.50-SQL");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/photo-gallery/#developers");

  exit(0);
}

CPE = "cpe:/a:10web:photo-gallery";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "1.3.51" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.51", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
