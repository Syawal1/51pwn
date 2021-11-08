###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox ESR Multiple Vulnerabilities-01 May14 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804565");
  script_version("2020-08-11T09:13:39+0000");
  script_cve_id("CVE-2014-1518", "CVE-2014-1520", "CVE-2014-1523", "CVE-2014-1524",
                "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_bugtraq_id(67123, 67126, 67129, 67131, 67135, 67137, 67134, 67130);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-11 09:13:39 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-05-06 15:58:04 +0530 (Tue, 06 May 2014)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 May14 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox ESR and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Using certain temp directory within maintenservice_installer.exe in an
  insecure way.

  - An error exists when validating the XBL status of an object.

  - An error exists when handling site notifications within the Web Notification
  API.

  - An error exists when handling browser navigations through history to load a
  website.

  - A use-after-free error exists when handling an imgLoader object within the
  'nsGenericHTMLElement::GetWidthHeightForImage()' function.

  - An error exists in NSS.

  - A use-after-free error exists when handling host resolution within the
  'libxul.so!nsHostResolver::ConditionallyRefreshRecord()' function.

  - And some unspecified errors exist.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct spoofing attacks,
disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system.");
  script_tag(name:"affected", value:"Mozilla Firefox ESR version 24.x before 24.5 on Mac OS X");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 24.5 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58234");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-34.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(ffVer =~ "^24\." && version_in_range(version:ffVer,
                       test_version:"24.0", test_version2:"24.4"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
