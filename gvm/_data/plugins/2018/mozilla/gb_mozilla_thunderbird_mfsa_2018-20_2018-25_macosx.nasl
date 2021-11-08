###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Security Updates(mfsa_2018-20_2018-25)-MAC OS X
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814071");
  script_version("2020-10-20T05:31:32+0000");
  script_cve_id("CVE-2018-12377", "CVE-2018-12378", "CVE-2018-18499", "CVE-2018-12379", "CVE-2017-16541",
                "CVE-2018-12385", "CVE-2018-12383", "CVE-2018-12376");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-20 05:31:32 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2018-10-05 11:08:43 +0530 (Fri, 05 Oct 2018)");
  script_name("Mozilla Thunderbird Security Updates (mfsa_2018-20_2018-25) - MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An use-after-free error in refresh driver timers.

  - An use-after-free error in IndexedDB.

  - A same-origin policy violation using meta refresh and performance.getEntries to steal cross-origin URLs.

  - An out-of-bounds write error with malicious MAR file.

  - A proxy bypass using automount and autofs.

  - An error related to cached data in the user profile directory.

  - An error related to setting of a master password.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information, cause denial of service, run arbitrary code
  and bypass security restrictions.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 60.2.1 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 60.2.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-25");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"60.2.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"60.2.1", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
