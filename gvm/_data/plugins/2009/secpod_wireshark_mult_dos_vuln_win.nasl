###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901031");
  script_version("2020-04-27T09:00:11+0000");
  script_tag(name:"last_modification", value:"2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3242", "CVE-2009-3243");
  script_bugtraq_id(36408);
  script_name("Wireshark Multiple Denial of Service Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36754");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-06.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3893");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4008");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service condition.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.1 on Windows");
  script_tag(name:"insight", value:"- An unspecified error in 'packet.c' in the GSM A RR dissector caused via
    unknown vectors related to 'an uninitialized dissector handle, ' which
    triggers an assertion failure.

  - An unspecified error in the TLS dissector which can be exploited via
    unknown vectors related to TLS 1.2 conversations.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.2.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple
  Denial of Service vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer)
  exit(0);

if(version_in_range(version:sharkVer, test_version:"1.2.0", test_version2:"1.2.1")){
  report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"1.2.0 - 1.2.1");
  security_message(port: 0, data: report);
}
