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
  script_oid("1.3.6.1.4.1.25623.1.0.815430");
  script_version("2020-05-15T09:02:11+0000");
  script_cve_id("CVE-2019-13962");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-05-15 09:02:11 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2019-07-24 17:42:18 +0530 (Wed, 24 Jul 2019)");

  script_name("VLC Media Player 'avcodec picture copy' Heap Buffer Overflow Vulnerability (Mac OS X)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");

  script_xref(name:"URL", value:"https://www.videolan.org/security/sb-vlc308.html");
  script_xref(name:"URL", value:"https://trac.videolan.org/vlc/ticket/22240");

  script_tag(name:"summary", value:"The host is installed with VLC media player
  and is prone to a heap-based buffer over-read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a heap-based buffer
  over-read error in lavc_CopyPicture in modules/codec/avcodec/video.c due to
  insufficient validation of width and height.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  cause a denial-of-service condition, denying service to legitimate users and
  may also be able to execute arbitrary code.");

  script_tag(name:"affected", value:"VideoLAN VLC media player version through 3.0.7 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 3.0.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

ver = infos["version"];
path = infos["location"];

if(version_is_less(version:ver, test_version:"3.0.8")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"3.0.8", install_path: path);
  security_message(data:report);
  exit(0);
}

exit(99);
