###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Code Execution and DoS Vulnerabilities (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903015");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2012-0772", "CVE-2012-0773", "CVE-2012-0724", "CVE-2012-0725");
  script_bugtraq_id(52748, 52916, 52914);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2012-03-30 11:21:49 +0530 (Fri, 30 Mar 2012)");
  script_name("Adobe Flash Player Code Execution and DoS Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48623/");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026859");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-07.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via unknown vectors.");
  script_tag(name:"affected", value:"Adobe Flash Player version prior to 10.3.183.18 and 11.x to 11.1.102.63 on Linux");
  script_tag(name:"insight", value:"The flaws are due to an unspecified error within the NetStream class.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 10.3.183.18 or 11.2.202.228 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  code execution and denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!vers)
  exit(0);

vers = ereg_replace(pattern:",", string:vers, replace: ".");
if(vers) {
  if(version_is_less(version:vers, test_version:"10.3.183.18") ||
     version_in_range(version:vers, test_version:"11.0", test_version2:"11.1.102.63")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}