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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:premiere_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817602");
  script_version("2020-11-04T09:25:23+0000");
  script_cve_id("CVE-2020-24424");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-11-04 09:25:23 +0000 (Wed, 04 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-10-21 11:26:46 +0530 (Wed, 21 Oct 2020)");
  script_name("Adobe Premiere Pro RCE Vulnerability-APSB20-64 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Adobe Premiere
  Pro and is prone to RCE vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to presence of an
  uncontrolled search path element.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Adobe Premiere Pro 14.4 and prior on Windows");

  script_tag(name:"solution", value:"Upgrade Adobe Premiere Pro to version 14.5
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb20-63.html");

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_premiere_pro_detect_win.nasl");
  script_mandatory_keys("adobe/premierepro/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
adobeVer = infos['version'];
adobePath = infos['location'];

if(version_is_less(version:adobeVer, test_version:"14.5"))
{
  report = report_fixed_ver(installed_version:adobeVer, fixed_version:'14.5', install_path:adobePath);
  security_message(data: report);
  exit(0);
}
exit(0);
