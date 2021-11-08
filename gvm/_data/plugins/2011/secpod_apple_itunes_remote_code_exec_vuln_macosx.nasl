###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Remote Code Execution Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902639");
  script_version("2020-02-28T13:41:47+0000");
  script_cve_id("CVE-2008-3434");
  script_bugtraq_id(50672);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"creation_date", value:"2011-11-28 16:04:18 +0530 (Mon, 28 Nov 2011)");
  script_name("Apple iTunes Remote Code Execution Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5030");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4981");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011/Nov/msg00003.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("secpod_itunes_detect_macosx.nasl");
  script_mandatory_keys("Apple/iTunes/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the user running the affected application.");

  script_tag(name:"affected", value:"Apple iTunes version prior to 10.5.1 on Mac OS X.");

  script_tag(name:"insight", value:"The flaw is due to the improper verification of authenticity of
  updates, allows man-in-the-middle attack execute arbitrary code via a Trojan horse update.");

  script_tag(name:"solution", value:"Upgrade to Apple Apple iTunes version 10.5.1 or later.");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes and is prone to remote
  code execution vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"10.5.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.5.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
