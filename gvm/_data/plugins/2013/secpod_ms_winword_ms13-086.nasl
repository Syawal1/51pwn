###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Word Remote Code Execution Vulnerabilities (2885084)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.903405");
  script_version("2019-12-20T12:48:41+0000");
  script_cve_id("CVE-2013-3891", "CVE-2013-3892");
  script_bugtraq_id(62827, 62832);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-20 12:48:41 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"creation_date", value:"2013-10-09 09:05:43 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (2885084)");


  script_tag(name:"summary", value:"This host is missing an important security update according to
Microsoft Bulletin MS13-086.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"Multiple flaws are due to error when processing Microsoft Word binary
documents can be exploited to cause a memory corruption");
  script_tag(name:"affected", value:"- Microsoft Word 2003 Service Pack 3 and prior

  - Microsoft Word 2007 Service Pack 3  and prior");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
code, cause memory corruption and compromise the system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2826020");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2827330");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-086");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

winwordVer = get_kb_item("SMB/Office/Word/Version");

## Microsoft Office Word 2003/2007
if(winwordVer && winwordVer =~ "^(11|12).*")
{
  if(version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8406") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6683.5001"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
