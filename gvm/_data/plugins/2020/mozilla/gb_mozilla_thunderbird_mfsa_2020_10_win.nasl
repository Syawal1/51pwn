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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816705");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6811",
                "CVE-2019-20503", "CVE-2020-6812", "CVE-2020-6814");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-03-16 14:57:10 +0530 (Mon, 16 Mar 2020)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2020-10)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A use-after-free when removing data about origins.

  - Multiple out-of-bounds read issues.

  - A use-after-free issue in cubeb during stream destruction.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  disclose sensitive information, run arbitrary code, inject arbitrary commands
  and crash the affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  68.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 68.6
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-10/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"68.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"68.6", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
