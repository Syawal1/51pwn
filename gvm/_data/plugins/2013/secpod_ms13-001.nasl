###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Print Spooler Remote Code Execution Vulnerability (2769369)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901213");
  script_version("2019-12-20T12:48:41+0000");
  script_cve_id("CVE-2013-0011");
  script_bugtraq_id(57142);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-20 12:48:41 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"creation_date", value:"2013-01-09 09:01:35 +0530 (Wed, 09 Jan 2013)");
  script_name("Microsoft Windows Print Spooler Remote Code Execution Vulnerability (2769369)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2769369");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-001");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code by sending a specially crafted print job to the print server.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");
  script_tag(name:"insight", value:"The vulnerability is caused when the Windows Print Spooler fails to handle
  a specially crafted print job.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-001.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32spl.dll");
if(!exeVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.1.7600.17162") ||
     version_in_range(version:exeVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21364")||
     version_in_range(version:exeVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17993")||
     version_in_range(version:exeVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22155")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
