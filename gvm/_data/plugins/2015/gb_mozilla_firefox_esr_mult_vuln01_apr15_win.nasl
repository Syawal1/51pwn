###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox ESR Multiple Vulnerabilities-01 Apr15 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805524");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2015-0816", "CVE-2015-0815", "CVE-2015-0807", "CVE-2015-0801");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2015-04-06 15:40:14 +0530 (Mon, 06 Apr 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 Apr15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper restriction of resource: URLs.

  - Multiple unspecified errors.

  - An error in 'navigator.sendBeacon' implementation.

  - An error allowing to bypass the Same Origin Policy.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary JavaScript code, conduct cross-site request
  forgery (CSRF) attacks, conduct denial of service (memory corruption and
  application crash) attack and possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR 31.x before 31.6 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version
  31.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-33");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-30");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-37");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-40");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^31\.")
{
  if((version_in_range(version:vers, test_version:"31.0", test_version2:"31.5")))
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     ' + "31.6"  + '\n';
    security_message(data:report);
    exit(0);
  }
}
