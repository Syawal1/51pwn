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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:google:chrome";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817074");
  script_version("2020-07-28T07:05:49+0000");
  script_cve_id("CVE-2020-6509");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-28 07:05:49 +0000 (Tue, 28 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-03 09:37:26 +0530 (Fri, 03 Jul 2020)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google Chrome Use After Free In Extensions Vulnerability (MacOSX)-June 2020");

  script_tag(name:"summary", value:"This host is installed with Google Chrome
  and is prone to a vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to use-after-free error
  in extensions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute code on the host.");

  script_tag(name:"affected", value:"Google Chrome before 83.0.4103.116 on MacOSX.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome Version version 83.0.4103.116
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/06/stable-channel-update-for-desktop_22.html");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

Ver = infos["version"];
path = infos["location"];

if(version_is_less(version:Ver, test_version:"83.0.4103.116"))
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:"83.0.4103.116", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
