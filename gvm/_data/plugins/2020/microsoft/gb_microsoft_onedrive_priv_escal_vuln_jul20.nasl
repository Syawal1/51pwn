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

CPE = "cpe:/a:microsoft:onedrive";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817318");
  script_version("2020-07-30T04:31:19+0000");
  script_cve_id("CVE-2020-1465");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-07-30 04:31:19 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 11:50:35 +0530 (Mon, 27 Jul 2020)");
  script_name("Microsoft OneDrive Privilege Escalation Vulnerability - July 2020");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Updates for month of July");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Microsoft
  OneDrive that allows file deletion in arbitrary locations.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges.");

  script_tag(name:"affected", value:"Microsoft OneDrive prior to version 20.114.0607.0002.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1465");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/office/onedrive-release-notes-845dcf18-f921-435e-bf28-4e24b95e5fc0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_onedrive_detect_win.nasl");
  script_mandatory_keys("microsoft/onedrive/win/detected");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'] ;
path = infos['location'];

if(!version || version =~ "Unknown"){
  exit(0);
}

if(version_is_less(version:version, test_version:"20.114.0607.0002"))
{
  report = report_fixed_ver(installed_version:version, fixed_version: "20.114.0607.0002");
  security_message(data:report);
  exit(0);
}
exit(0);
