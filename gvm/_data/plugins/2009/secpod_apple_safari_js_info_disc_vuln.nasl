###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari JavaScript Engine Cross Domain Information Disclosure Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900075");
  script_version("2020-02-28T13:41:47+0000");
  script_tag(name:"last_modification", value:"2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5914");
  script_bugtraq_id(33276);
  script_name("Apple Safari JavaScript Engine Cross Domain Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.trusteer.com/files/In-session-phishing-advisory-2.pdf");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in
  the context of the web browser and can spoof sensitive information of the remote user through the web browser.");

  script_tag(name:"affected", value:"Apple Safari 3.1.2 and prior on Windows.");

  script_tag(name:"insight", value:"Undefined function in the JavaScript implementation of the browser fails
  to properly enforce the origin policy and leaves temporary footprints.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.0 or later.");

  script_tag(name:"summary", value:"The host is running Apple Safari web browser which is prone
  to information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"3.525.21.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
