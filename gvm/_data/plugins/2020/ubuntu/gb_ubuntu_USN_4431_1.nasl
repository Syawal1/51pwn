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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844502");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2018-15822", "CVE-2019-11338", "CVE-2019-12730", "CVE-2019-13312", "CVE-2019-13390", "CVE-2019-17539", "CVE-2019-17542", "CVE-2020-12284", "CVE-2020-13904");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-07-24 07:28:01 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-23 03:00:56 +0000 (Thu, 23 Jul 2020)");
  script_name("Ubuntu: Security Advisory for ffmpeg (USN-4431-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"USN", value:"4431-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005523.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the USN-4431-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FFmpeg incorrectly verified empty audio packets or
HEVC data. An attacker could possibly use this issue to cause a denial of
service via a crafted file. This issue only affected Ubuntu 16.04 LTS, as
it was already fixed in Ubuntu 18.04 LTS.

It was discovered that FFmpeg incorrectly handled sscanf failures. An
attacker could possibly use this issue to cause a denial of service or
other unspecified impact. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS. (CVE-2019-12730)

It was discovered that FFmpeg incorrectly handled certain WEBM files. An
attacker could possibly use this issue to obtain sensitive data or other
unspecified impact. This issue only affected Ubuntu 20.04 LTS.
(CVE-2019-13312)

It was discovered that FFmpeg incorrectly handled certain AVI files. An
attacker could possibly use this issue to cause a denial of service or
other unspecified impact. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS. (CVE-2019-13390)

It was discovered that FFmpeg incorrectly handled certain input. An
attacker could possibly use this issue to cause a denial of service or
other unspecified impact. This issue only affected Ubuntu 18.04 LTS.
(CVE-2019-17539)

It was discovered that FFmpeg incorrectly handled certain input during
decoding of VQA files. An attacker could possibly use this issue to
obtain sensitive information or other unspecified impact. This issue
only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-17542)

It was discovered that FFmpeg incorrectly handled certain JPEG files. An
attacker could possibly use this issue to obtain sensitive information
or other unspecified impact. This issue only affected Ubuntu 20.04 LTS.
(CVE-2020-12284)

It was discovered that FFmpeg incorrectly handled certain M3U8 files. An
attacker could possibly use this issue to obtain sensitive information
or other unspecified impact. (CVE-2020-13904)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra57", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec57", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice57", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra6", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter6", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat57", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample3", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil55", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc54", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample2", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale4", ver:"7:3.4.8-0ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-ffmpeg-extra56", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-ffmpeg56", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice-ffmpeg56", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-ffmpeg5", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-ffmpeg56", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample-ffmpeg2", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil-ffmpeg54", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc-ffmpeg53", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample-ffmpeg1", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale-ffmpeg3", ver:"7:2.8.17-0ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra58", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec58", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice58", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra7", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter7", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat58", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample4", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil56", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc55", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample3", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale5", ver:"7:4.2.4-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
