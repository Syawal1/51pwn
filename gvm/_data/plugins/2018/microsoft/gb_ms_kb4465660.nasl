###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows Security Bypass and Latest Servicing Stack Updates-Defense in Depth (KB4465660)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814273");
  script_version("2020-11-24T10:56:53+0000");
  script_cve_id("CVE-2018-8566");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-24 10:56:53 +0000 (Tue, 24 Nov 2020)");
  script_tag(name:"creation_date", value:"2018-11-14 10:15:34 +0530 (Wed, 14 Nov 2018)");
  script_name("MS Windows Security Bypass and Latest Servicing Stack Updates-Defense in Depth (KB4465660)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4465660.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"A security feature bypass flaw exists when
  Windows improperly suspends BitLocker Device Encryption. Also Microsoft has
  released latest servicing stack updates that provides enhanced security as a
  defense in depth measure.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass a security control.");

  script_tag(name:"affected", value:"Microsoft Windows 10 version 1703 for 32-bit/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4465660");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8566");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV990001");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "WMI/access_successful");
  script_exclude_keys("win/lsc/disable_wmi_search");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("wmi_file.inc");
include("list_array_func.inc");
include("misc_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0)
  exit(0);

infos = kb_smb_wmi_connectinfo();
if(!infos)
  exit(0);

handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
if(!handle)
  exit(0);

fileList = wmi_file_fileversion(handle:handle, fileName:"smiengine", fileExtn:"dll", includeHeader:FALSE);
wmi_close(wmi_handle:handle);
if(!fileList || !is_array(fileList))
  exit(0);

max_version = ""; # nb: To make openvas-nasl-lint happy...
foreach filePath(keys(fileList)) {

  vers = fileList[filePath];
  if(vers =~ "^10\.0" && version = eregmatch(string:vers, pattern:"^([0-9.]+)")) {
    if(max_version && version_is_less_equal(version:version[1], test_version:max_version)) {
      continue;
    } else {
      max_version = version[1];
      path = filePath;
    }
  }
}

if(max_version && version_in_range(version:max_version, test_version:"10.0.15063.0", test_version2:"10.0.15063.1440")) {
  report = report_fixed_ver(file_checked:path,
                            file_version:max_version, vulnerable_range:"10.0.15063.0 - 10.0.15063.1440");
  security_message(data:report);
  exit(0);
}

exit(99);
