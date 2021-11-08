# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815735");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2019-1453", "CVE-2019-1458", "CVE-2019-1465", "CVE-2019-1466",
                "CVE-2019-1467", "CVE-2019-1468", "CVE-2019-1469", "CVE-2019-1470",
                "CVE-2019-1474", "CVE-2019-1484", "CVE-2019-1485", "CVE-2019-1488");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-12-11 11:44:25 +0530 (Wed, 11 Dec 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4530702)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4530702");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Win32k component fails to properly handle objects in memory

  - win32k component improperly provides kernel information.

  - Windows kernel improperly handles objects in memory.

  - Microsoft Defender improperly handles specific buffers.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to elevate privileges, execute arbitrary code, read unauthorized
  information, bypass secuirty restrictions and cause denial of service.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4530702");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

fileVer = fetch_file_version(sysPath:sysPath, file_name:"inetcomm.dll");
if(!fileVer)
  exit(0);

if(version_is_less(version:fileVer, test_version:"6.3.9600.19572")) {
  report = report_fixed_ver(file_checked:sysPath + "\Inetcomm.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.3.9600.19572");
  security_message(data:report);
  exit(0);
}

exit(99);
