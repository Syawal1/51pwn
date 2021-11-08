###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Multiple Vulnerabilities-04 January13 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803205");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2013-0764", "CVE-2013-0768", "CVE-2013-0757", "CVE-2013-0745",
                "CVE-2013-0747", "CVE-2013-0752", "CVE-2013-0755", "CVE-2013-0756");
  script_bugtraq_id(57211, 57204, 57236, 57240, 57241, 57213, 57215);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-01-16 16:55:41 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla Products Multiple Vulnerabilities-04 January13 (Mac OS X)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51752/");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027955");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027957");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027958");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-03.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-07.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-08.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-10.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-13.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-14.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-18.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-19.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, cause a denial of service or execute
  arbitrary code in the context of the browser.");

  script_tag(name:"affected", value:"SeaMonkey version before 2.15 on Mac OS X

  Thunderbird version before 17.0.2 on Mac OS X

  Mozilla Firefox version before 18.0 on Mac OS X

  Thunderbird ESR version 17.x before 17.0.2 on Mac OS X

  Mozilla Firefox ESR version 17.x before 17.0.2 on Mac OS X");

  script_tag(name:"insight", value:"- An error exists within the 'nsSOCKSSocketInfo::ConnectToProxy()' when
    handling SSL connection threads.

  - An error when parsing height and width values of a canvas element.

  - An error within the 'Object.prototype.__proto__()' can be exploited to
    bypass Chrome Object Wrappers (COW).

  - Unspecified error in the browser engine can be exploited to corrupt memory.

  - An error exists due to the AutoWrapperChanger class not keeping certain
    objects alive during garbage collection.");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox/Thunderbird/Seamonkey and is
  prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 18.0 or ESR version 17.0.2 or later, upgrade to SeaMonkey version to 2.15 or later,
  upgrade to Thunderbird version to 17.0.2 or ESR 17.0.2 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
esrvers = get_kb_item("Mozilla/Firefox-ESR/MacOSX/Version");
if(vers || esrvers) {
  if(version_is_less(version:vers, test_version:"18.0") ||
     version_in_range(version:esrvers, test_version:"17.0", test_version2:"17.0.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("SeaMonkey/MacOSX/Version");
if(vers) {
  if(version_is_less(version:vers, test_version:"2.15"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
esrvers = get_kb_item("Thunderbird-ESR/MacOSX/Version");
if(vers || esrvers) {
  if(version_is_less(version:vers, test_version:"17.0.2") ||
     version_in_range(version:esrvers, test_version:"17.0", test_version2:"17.0.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}