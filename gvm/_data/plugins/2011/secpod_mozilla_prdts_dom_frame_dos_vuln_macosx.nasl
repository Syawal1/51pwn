###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products DOM Frame Denial of Service Vulnerability (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902776");
  script_version("2020-11-25T09:16:10+0000");
  script_cve_id("CVE-2011-3664");
  script_bugtraq_id(51137);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)");
  script_tag(name:"creation_date", value:"2011-12-22 12:45:21 +0530 (Thu, 22 Dec 2011)");
  script_name("Mozilla Products DOM Frame Denial of Service Vulnerability (MAC OS X)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51137/discuss");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-57.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service.");

  script_tag(name:"affected", value:"Thunderbird version prior to 9.0, SeaMonkey version prior to 2.6,
  Mozilla Firefox version prior to 9.0,");

  script_tag(name:"insight", value:"The flaw is due to an error within the plugin handler when deleting
  DOM frame can be exploited to dereference memory.");

  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/thunderbird and is prone
  to denial of service vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 9.0 or later, Upgrade to Thunderbird
  version to 9.0 or later, Upgrade to SeaMonkey version to 2.6 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"9.0"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"9.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"9.0"))
  {
   report = report_fixed_ver(installed_version:vers, fixed_version:"9.0");
   security_message(port: 0, data: report);
   exit(0);
  }
}

vers = get_kb_item("SeaMonkey/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.6")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.6");
    security_message(port: 0, data: report);
  }
}
