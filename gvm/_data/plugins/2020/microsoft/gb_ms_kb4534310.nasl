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
  script_oid("1.3.6.1.4.1.25623.1.0.815560");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2020-0607", "CVE-2020-0608", "CVE-2020-0611", "CVE-2020-0615",
                "CVE-2020-0620", "CVE-2020-0625", "CVE-2020-0626", "CVE-2020-0627",
                "CVE-2020-0628", "CVE-2020-0629", "CVE-2020-0630", "CVE-2020-0631",
                "CVE-2020-0632", "CVE-2020-0634", "CVE-2020-0635", "CVE-2020-0637",
                "CVE-2020-0639", "CVE-2020-0640", "CVE-2020-0642", "CVE-2020-0643");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-01-15 12:39:53 +0530 (Wed, 15 Jan 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4534310)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4534310");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist in Microsoft Scripting
  Engine, Windows Input and Composition, Windows Media, Windows Storage and
  Filesystems, and Windows Server.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, obtain information to further compromise the user's
  system, gain elevated privileges and break out of the Edge AppContainer sandbox
  and run processes in an elevated context.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4534310");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Mshtml.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"11.0.9600.19597"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Mshtml.dll",
                            file_version:fileVer, vulnerable_range:"Less than 11.0.9600.19597");
  security_message(data:report);
  exit(0);
}
exit(99);
