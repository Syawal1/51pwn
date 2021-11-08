# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817517");
  script_version("2020-11-13T09:01:15+0000");
  script_cve_id("CVE-2020-15969", "CVE-2020-15254", "CVE-2020-15680", "CVE-2020-15681",
                "CVE-2020-15682", "CVE-2020-15683", "CVE-2020-15684");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-13 09:01:15 +0000 (Fri, 13 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-10-21 10:21:34 +0530 (Wed, 21 Oct 2020)");
  script_name("Mozilla Firefox Security Updates(mfsa_2020-45_2020-46)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free in usersctp.

  - Undefined behavior in bounded channel of crossbeam rust crate.

  - Presence of external protocol handlers could be determined through image tags.

  - Multiple WASM threads may have overwritten each others&#39, stub table entries.

  - The domain associated with the prompt to open an external protocol could be spoofed to display the incorrect origin.

  - Memory safety bugs fixed in Firefox 82 and Firefox ESR 78.4.

  - Memory safety bugs fixed in Firefox 82.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial-of-service or execute arbitrary code
  on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  82 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 82
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-45/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"82"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"82", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
