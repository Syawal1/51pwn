###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Silverlight Information Disclosure Vulnerability (2890788)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901223");
  script_version("2020-06-09T08:59:39+0000");
  script_cve_id("CVE-2013-3896");
  script_bugtraq_id(62793);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2013-10-09 11:03:47 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Silverlight Information Disclosure Vulnerability (2890788)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-087.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"Flaw is caused when Silverlight improperly handles certain objects in
  memory.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain potentially
  sensitive information.");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2890788");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-087");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_silverlight_detect.nasl");
  script_mandatory_keys("Microsoft/Silverlight/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!msl_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(msl_ver=~ "^5\.")
{
  if(version_in_range(version:msl_ver, test_version:"5.0", test_version2:"5.1.20912.0"))
  {
    report = 'Silverlight version:  ' + msl_ver  + '\n' +
             'Vulnerable range:  5.0 - 5.1.20912.0' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}