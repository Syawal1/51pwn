###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Air Multiple Vulnerabilities -01 May 13 (Windows)
#
# Authors:
# Thanga prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803496");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2013-3335", "CVE-2013-3334", "CVE-2013-3333", "CVE-2013-3332",
                "CVE-2013-3331", "CVE-2013-3330", "CVE-2013-3329", "CVE-2013-3328",
                "CVE-2013-3327", "CVE-2013-3326", "CVE-2013-3325", "CVE-2013-3324",
                                                                   "CVE-2013-2728");
  script_bugtraq_id(59901, 59900, 59899, 59898, 59897, 59896, 59895,
                           59894, 59893, 59892, 59891, 59890, 59889);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-05-21 14:48:32 +0530 (Tue, 21 May 2013)");
  script_name("Adobe Air Multiple Vulnerabilities -01 May 13 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53419");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors.");
  script_tag(name:"affected", value:"Adobe Air before 3.7.0.1531 on Windows");
  script_tag(name:"insight", value:"Multiple memory corruption flaws due to improper sanitation of user
  supplied input via a file.");
  script_tag(name:"solution", value:"Update to Adobe Air version 3.7.0.1860 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"3.7.0.1530" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.7.0.1860", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
