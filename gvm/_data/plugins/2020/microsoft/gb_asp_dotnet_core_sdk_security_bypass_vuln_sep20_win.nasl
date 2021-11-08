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

CPE = "cpe:/a:microsoft:.netcore_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817388");
  script_version("2020-09-21T07:54:34+0000");
  script_cve_id("CVE-2020-1045");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-09-21 07:54:34 +0000 (Mon, 21 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-09 09:00:21 +0530 (Wed, 09 Sep 2020)");
  script_name(".NET Core SDK Security Feature Bypass Vulnerability (Sep 2020)");

  script_tag(name:"summary", value:"This host is installed with ASP.NET Core SDK
  and is prone to a security feature bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the way
  Microsoft ASP.NET Core parses encoded cookie names.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass security restrictions.");

  script_tag(name:"affected", value:"ASP.NET Core SDK 2.1.x prior to 2.1.518 and 3.1.x
  prior to 3.1.108");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/3.1/3.1.8/3.1.8.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.22/2.1.22.md");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1045");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys(".NET/Core/SDK/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
coreVers = infos['version'];
path = infos['location'];

if (coreVers =~ "^2\.1" && version_is_less(version:coreVers, test_version:"2.1.518")){
  fix = "2.1.518";
}

else if (coreVers =~ "^3\.1" && version_is_less(version:coreVers, test_version:"3.1.108")){
  fix = "3.1.108" ;
}

if(fix)
{
  report = report_fixed_ver(installed_version:coreVers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
