###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle VirtualBox Security Updates (apr2018-3678067) 01 - Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813302");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2018-2860", "CVE-2018-0739", "CVE-2018-2842", "CVE-2018-2843",
                "CVE-2018-2844", "CVE-2018-2845", "CVE-2018-2831", "CVE-2018-2830",
                "CVE-2018-2837", "CVE-2018-2836", "CVE-2018-2835");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2018-04-18 19:09:04 +0530 (Wed, 18 Apr 2018)");
  script_name("Oracle VirtualBox Security Updates (apr2018-3678067) 01 - Windows");

  script_tag(name:"summary", value:"The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in 'Core' component of Oracle VM VirtualBox.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to affect confidentiality, availability and integrity via
  unknown vectors.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.1.36, 5.2.x
  prior to 5.2.10 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox 5.2.10 or
  5.1.36 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
virtualVer = infos['version'];
path = infos['location'];

if(virtualVer =~ "^5\.2" && (version_is_less(version:virtualVer, test_version:"5.2.10"))){
  fix = "5.2.10";
}

else if(version_is_less(version:virtualVer, test_version:"5.1.36")){
  fix = "5.1.36";
}

if(fix)
{
  report = report_fixed_ver(installed_version:virtualVer, fixed_version: fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
