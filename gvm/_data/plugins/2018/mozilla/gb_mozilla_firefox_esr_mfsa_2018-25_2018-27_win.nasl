###############################################################################
# OpenVAS Vulnerability Test
# Id$
#
# Mozilla Firefox ESR Security Updates(mfsa_2018-24_2018-24)-Windows
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814416");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2018-12392", "CVE-2018-12395", "CVE-2018-12396", "CVE-2018-12397",
                "CVE-2018-12389", "CVE-2018-12390");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2018-10-24 15:55:23 +0530 (Wed, 24 Oct 2018)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2018-24_2018-24)-Windows");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Poor event handling in nested loops while opening a document through script.

  - A WebExtension can bypass domain restrictions through domain fronting.

  - A WebExtension can run content scripts in disallowed contexts following
    navigation or other events.

  - A WebExtension can request access to local files without the warning prompt.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, denial of service and cause denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 60.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 60.3
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-24");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"60.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"60.3", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
