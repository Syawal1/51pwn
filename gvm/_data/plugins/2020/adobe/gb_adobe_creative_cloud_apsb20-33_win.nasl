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

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817251");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2020-9669", "CVE-2020-9671", "CVE-2020-9670", "CVE-2020-9682");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 12:34:15 +0530 (Mon, 27 Jul 2020)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Update APSB20-33 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Creative
  cloud and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insecure file permissions vulnerability error.

  - Multiple symlink error.

  - Lack of Exploit Mitigations.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to arbitrary file system write and escalate privileges on the target system.");

  script_tag(name:"affected", value:"Adobe Creative Cloud 5.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Creative Cloud version
  5.2. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb20-33.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
cloudVer = infos['version'];
cloudPath = infos['location'];

if(version_is_less(version:cloudVer, test_version:"5.2"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"5.2", install_path:cloudPath);
  security_message(data:report);
  exit(0);
}
exit(0);