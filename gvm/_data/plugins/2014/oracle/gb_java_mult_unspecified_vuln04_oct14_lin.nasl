###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-04 Oct 2014 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108418");
  script_version("2020-05-12T13:57:17+0000");
  script_cve_id("CVE-2014-6562", "CVE-2014-6485", "CVE-2014-6468");
  script_bugtraq_id(70523, 70519, 70488);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-05-12 13:57:17 +0000 (Tue, 12 May 2020)");
  script_tag(name:"creation_date", value:"2014-10-20 13:53:18 +0530 (Mon, 20 Oct 2014)");

  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-04 Oct 2014 (Linux)");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE JRE
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in the Hotspot subcomponent related to missing checksum
    verification of archive files.

  - An error related to the JavaFX subcomponent.

  - Another unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to manipulate certain data, gain elevated privileges, and execute arbitrary code.");

  script_tag(name:"affected", value:"Oracle Java SE 8 update 20 and prior on
  Linux");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61609/");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[78]") {
  if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.20")) {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"1.8.0 - 1.8.0.20");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
