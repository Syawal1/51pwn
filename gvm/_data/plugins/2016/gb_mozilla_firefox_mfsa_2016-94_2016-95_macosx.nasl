###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Security Updates(mfsa_2016-94_2016-95)-MAC OS X
#
# Authors:
# kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809837");
  script_version("2020-10-23T13:29:00+0000");
  script_cve_id("CVE-2016-9894", "CVE-2016-9899", "CVE-2016-9895", "CVE-2016-9896",
  "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9900", "CVE-2016-9904",
  "CVE-2016-9901", "CVE-2016-9902", "CVE-2016-9903", "CVE-2016-9080",
  "CVE-2016-9893");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"creation_date", value:"2016-12-15 13:39:52 +0530 (Thu, 15 Dec 2016)");
  script_name("Mozilla Firefox Security Updates( mfsa_2016-94_2016-95 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error in SkiaGL.

  - An use-after-free error while manipulating DOM events and audio elements.

  - A CSP bypass error using marquee tag.

  - An Use-after-free error with WebVR.

  - A memory corruption error in libGLES.

  - An use-after-free error in Editor while manipulating DOM subtrees.

  - The restricted external resources can be loaded by SVG images through data URLs.

  - A cross-origin information leak error in shared atoms.

  - The data from Pocket server improperly sanitized before execution.

  - The pocket extension does not validate the origin of events.

  - An XSS injection vulnerability in add-ons SDK.

  - Some memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service, gain sensitive information and also
  could run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  50.1 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox 50.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-94");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"50.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"50.1");
  security_message(data:report);
  exit(0);
}
