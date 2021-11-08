###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Shell Remote Code Execution Vulnerability (2286198)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-13
#      - To detect file version 'Shell32.dll' on vista, win 2008 and win 7
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902226");
  script_version("2020-04-23T12:22:09+0000");
  script_tag(name:"last_modification", value:"2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)");
  script_tag(name:"creation_date", value:"2010-08-04 08:26:41 +0200 (Wed, 04 Aug 2010)");
  script_cve_id("CVE-2010-2568");
  script_bugtraq_id(41732);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Shell Remote Code Execution Vulnerability (2286198)");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/940193");
  script_xref(name:"URL", value:"http://www.ivanlef0u.tuxfamily.org/?p=411");
  script_xref(name:"URL", value:"http://isc.sans.edu/diary.html?storyid=9190");
  script_xref(name:"URL", value:"http://isc.sans.edu/diary.html?storyid=9181");
  script_xref(name:"URL", value:"http://community.websense.com/blogs/securitylabs/archive/2010/07/20/microsoft-lnk-vulnerability-brief-technical-analysis-cve-2010-2568.aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to automatically execute
  a malicious binary by tricking a user into browsing a remote network or WebDAV
  share, or opening in Windows Explorer a removable drive containing a specially
  crafted shortcut file.");
  script_tag(name:"affected", value:"- Microsoft Windows 7

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");
  script_tag(name:"insight", value:"The flaw is due to an error in Windows 'Shell' when parsing shortcuts
  (.lnk or .pif), certain parameters are not properly validated when attempting
  to load the icon.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-046.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-046");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"2286198") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Shell32.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.2900.6018")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.2900.6018", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.3790.4751")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.3790.4751", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Shell32.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18505")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18505", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18287")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18287", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18505")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18505", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18287")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18287", install_path:sysPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
 security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16644")){
     report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.1.7600.16644", install_path:sysPath);
     security_message(port: 0, data: report);
  }
}
