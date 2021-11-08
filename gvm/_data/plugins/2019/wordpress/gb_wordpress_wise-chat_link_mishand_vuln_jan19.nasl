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
  script_oid("1.3.6.1.4.1.25623.1.0.112532");
  script_version("2020-11-10T11:45:08+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-03-06 11:13:00 +0100 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2019-6780");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Wise Chat Plugin < 2.7 Mashandling of External Links Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wise-chat/detected");

  script_tag(name:"summary", value:"The WordPress plugin Wise Chat mishandles external links because
  rendering/filters/post/WiseChatLinksPostFilter.php omits noopener and noreferrer.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"WordPress Wise Chat plugin before version 2.7.");
  script_tag(name:"solution", value:"Update to version 2.7 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wise-chat/#developers");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46247");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/2016929/wise-chat/trunk/src/rendering/filters/post/WiseChatLinksPostFilter.php");

  exit(0);
}

CPE = "cpe:/a:kainex:wise-chat";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.7" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
