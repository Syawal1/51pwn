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
  script_oid("1.3.6.1.4.1.25623.1.0.817103");
  script_version("2020-06-09T06:40:15+0000");
  script_cve_id("CVE-2020-1108", "CVE-2020-0605", "CVE-2020-1066");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-09 06:40:15 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-13 09:18:00 +0530 (Wed, 13 May 2020)");
  script_name("Microsoft .NET Framework Multiple Vulnerabilities (KB4556399)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4556399");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Microsoft .NET Framework fails to check the source markup of a file.

  - Microsoft .NET Framework improperly handles web requests.

  - An error in how .NET Framework activates COM objects.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain escalated privileges, conduct a denial-of-service condition and run
  arbitrary code in the context of the current user. If the current user is logged
  on with administrative user rights, an attacker could take control of the affected
  system.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2, 4.7, 4.7.1, 4.7.2, 4.8 for Microsoft Windows 7 SP1 and Microsoft Windows Server 2008 R2 SP1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4556399/kb4556399");
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

if(!registry_key_exists(key:"SOFTWARE\Microsoft\.NETFramework")){
  if(!registry_key_exists(key:"SOFTWARE\Microsoft\ASP.NET")){
    if(!registry_key_exists(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\")){
      exit(0);
    }
  }
}


key_list = make_list("SOFTWARE\Microsoft\.NETFramework\", "SOFTWARE\Microsoft\ASP.NET\", "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\");

foreach key(key_list)
{
  if(".NETFramework" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      NetPath = registry_get_sz(key:key + item, item:"InstallRoot");
      if(NetPath && "\Microsoft.NET\Framework" >< NetPath)
      {
        foreach item (registry_enum_keys(key:key))
        {
          dotPath = NetPath + item;
          dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.identitymodel.dll");
          if(dllVer)
          {
            ## https://support.microsoft.com/en-us/help/4552940/kb4552940
            ## https://support.microsoft.com/en-us/help/4552920/kb4552920
            ## https://support.microsoft.com/en-us/help/4552919/kb4552919
            ## https://support.microsoft.com/en-us/help/4552921/kb4552921
            if(version_in_range(version:dllVer, test_version:"3.0", test_version2:"3.0.4506.8840"))
            {
              vulnerable_range = "3.0 - 3.0.4506.8840" ;
              break;
            }
            else if(version_in_range(version:dllVer, test_version:"4.0", test_version2:"4.0.30319.36626"))
            {
              vulnerable_range = "4.0 - 4.0.30319.36626" ;
              break;
            }
            else if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.7.3619"))
            {
              vulnerable_range = "4.6 - 4.7.3619" ;
              break;
            }
            else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4179"))
            {
              vulnerable_range = "4.8 - 4.8.4179" ;
              break;
            }
          }
        }
      }
    }
  }

  if((!vulnerable_range) && "ASP.NET" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      dotPath = registry_get_sz(key:key + item, item:"Path");
      if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
      {
        dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.identitymodel.dll");
        if(dllVer)
        {
          ## https://support.microsoft.com/en-us/help/4552940/kb4552940
          ## https://support.microsoft.com/en-us/help/4552920/kb4552920
          ## https://support.microsoft.com/en-us/help/4552919/kb4552919
          ## https://support.microsoft.com/en-us/help/4552921/kb4552921
          if(version_in_range(version:dllVer, test_version:"3.0", test_version2:"3.0.4506.8840"))
          {
            vulnerable_range = "3.0 - 3.0.4506.8840" ;
            break;
          }
          else if(version_in_range(version:dllVer, test_version:"4.0", test_version2:"4.0.30319.36626"))
          {
            vulnerable_range = "4.0 - 4.0.30319.36626" ;
            break;
          }
          else if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.7.3619"))
          {
            vulnerable_range = "4.6 - 4.7.3619" ;
            break;
          }
          else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4179"))
          {
            vulnerable_range = "4.8 - 4.8.4179" ;
            break;
          }
        }
      }
    }
  }

  ## For versions greater than 4.5 (https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_b)
  if((!vulnerable_range) && "NET Framework Setup" >< key)
  {
    dotPath = registry_get_sz(key:key, item:"InstallPath");
    if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
    {
      dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.identitymodel.dll");
      if(dllVer)
      {
        ## https://support.microsoft.com/en-us/help/4552940/kb4552940
        ## https://support.microsoft.com/en-us/help/4552920/kb4552920
        ## https://support.microsoft.com/en-us/help/4552919/kb4552919
        ## https://support.microsoft.com/en-us/help/4552921/kb4552921
        if(version_in_range(version:dllVer, test_version:"3.0", test_version2:"3.0.4506.8840"))
        {
          vulnerable_range = "3.0 - 3.0.4506.8840" ;
          break;
        }
        else if(version_in_range(version:dllVer, test_version:"4.0", test_version2:"4.0.30319.36626"))
        {
          vulnerable_range = "4.0 - 4.0.30319.36626" ;
          break;
        }
        else if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.7.3619"))
        {
          vulnerable_range = "4.6 - 4.7.3619" ;
          break;
        }
        else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4179"))
        {
          vulnerable_range = "4.8 - 4.8.4179" ;
          break;
        }
      }
    }
  }

  if(vulnerable_range)
  {
    report = report_fixed_ver(file_checked:dotPath + "System.identitymodel.dll",
                              file_version:dllVer, vulnerable_range:vulnerable_range);
    security_message(data:report);
    exit(0);
  }
}
exit(99);
