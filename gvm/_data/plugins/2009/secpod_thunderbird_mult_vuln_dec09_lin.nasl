###############################################################################
# OpenVAS Vulnerability Test
#
# Thunderbird Multiple Vulnerabilities Dec-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902008");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3981", "CVE-2009-3982");
  script_bugtraq_id(37361, 37362, 37363, 37364);
  script_name("Thunderbird Multiple Vulnerabilities Dec-09 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37699");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3547");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-65.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Thunderbird/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code via
  unknown vectors or compromise a user's system.");
  script_tag(name:"affected", value:"Thunderbird version 3.0 and prior on Linux.");
  script_tag(name:"insight", value:"Memory corruption error due to multiple unspecified flaws in the browser
  engine, which can be exploited via unknown vectors.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 3.0.1 or later.");
  script_tag(name:"summary", value:"The host is installed with Thunderbird browser and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird/Linux/Ver");
if(vers)
{
  if(version_is_less_equal(version:vers, test_version:"3.0")){
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 3.0");
    security_message(port: 0, data: report);
  }
}
