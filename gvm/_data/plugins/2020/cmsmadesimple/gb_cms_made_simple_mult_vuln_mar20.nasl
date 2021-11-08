# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113655");
  script_version("2020-09-11T07:08:52+0000");
  script_tag(name:"last_modification", value:"2020-09-11 07:08:52 +0000 (Fri, 11 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-03-24 09:36:57 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2020-10681", "CVE-2020-10682");

  script_name("CMS Made Simple <= 2.2.13 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cms_made_simple_detect.nasl");
  script_mandatory_keys("cmsmadesimple/installed");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Stored XSS vulnerability by sending a crafted .pxd file
    via the m1_files[] parameter to admin/moduleinterface.php

  - Remote Code Execution vulnerability by sending a crafted
    .php.jpegd JPEG file via the m1_files[] parameter to admin/moduleinterface.php");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  inject arbitrary HTML or JavaScript into the site or
  execute arbitrary commands on the target machine.");

  script_tag(name:"affected", value:"CMS Made Simple through version 2.2.13.");

  script_tag(name:"solution", value:"No known solution is available as of 11th September, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"http://dev.cmsmadesimple.org/bug/view/12274");
  script_xref(name:"URL", value:"http://dev.cmsmadesimple.org/bug/view/12275");

  exit(0);
}

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "2.2.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
