# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815547");
  script_version("2020-10-22T06:41:10+0000");
  script_cve_id("CVE-2019-13602", "CVE-2019-14437", "CVE-2019-14438", "CVE-2019-14498",
                "CVE-2019-14533", "CVE-2019-14534", "CVE-2019-14535", "CVE-2019-14776",
                "CVE-2019-14777", "CVE-2019-14778", "CVE-2019-14970");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-22 06:41:10 +0000 (Thu, 22 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-08-20 15:30:25 +0530 (Tue, 20 Aug 2019)");
  script_name("VLC Media Player Multiple Vulnerabilities-sb-vlc308 (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");

  script_xref(name:"URL", value:"https://www.videolan.org/security/sb-vlc308.html");

  script_tag(name:"summary", value:"The host is installed with VLC Media Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Vulnerability details:

  - Buffer overflow in the MKV demuxer,

  - Buffer overflow in the FAAD decoder,

  - Buffer overflow in the OGG demuxer,

  - Buffer overflow in the ASF demuxer,

  - A use after free in the MKV demuxer,

  - A use after free in the ASF demuxer,

  - Fix a couple of integer underflows in the MP4 demuxer,

  - A null dereference in the dvdnav demuxer,

  - A null dereference in the ASF demuxer,

  - A null dereference in the AVI demuxer,

  - A division by zero in the CAF demuxer and

  - A division by zero in the ASF demuxer");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause denial of service condition and execute arbitrary code.");

  script_tag(name:"affected", value:"VLC Media Player before 3.0.8 on Mac OS X.");

  script_tag(name:"solution", value:"Update VLC Media Player to version 3.0.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"3.0.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.8", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);