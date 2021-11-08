###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Plugin Initialization Use-after-free Vulnerability- Apr15 (Windows)
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805544");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2015-2706");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-05-04 14:11:27 +0530 (Mon, 04 May 2015)");
  script_name("Mozilla Firefox Plugin Initialization Use-after-free Vulnerability- Apr15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to use-after-free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to a use-after-free
  error related to the 'AsyncPaintWaitEvent::AsyncPaintWaitEvent' function that
  is triggered when a race condition occurs when plugin initialization fails.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to conduct denial-of-service attack and potentially execute arbitrary
  code.");

  script_tag(name:"affected", value:"Mozilla Firefox before version 37.0.2
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 37.0.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-45");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"37.0.2"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "37.0.2"  + '\n';
  security_message(data:report);
  exit(0);
}
