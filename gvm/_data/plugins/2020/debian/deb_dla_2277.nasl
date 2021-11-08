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
  script_oid("1.3.6.1.4.1.25623.1.0.892277");
  script_version("2020-07-17T12:33:20+0000");
  script_cve_id("CVE-2018-6616", "CVE-2019-12973", "CVE-2020-15389", "CVE-2020-6851", "CVE-2020-8112");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-17 12:33:20 +0000 (Fri, 17 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-17 12:33:20 +0000 (Fri, 17 Jul 2020)");
  script_name("Debian LTS: Security Advisory for openjpeg2 (DLA-2277-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2277-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/931292");
  script_xref(name:"URL", value:"https://bugs.debian.org/950000");
  script_xref(name:"URL", value:"https://bugs.debian.org/950184");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the DLA-2277-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following CVEs were reported against src:openjpeg2.

CVE-2019-12973

In OpenJPEG 2.3.1, there is excessive iteration in the
opj_t1_encode_cblks function of openjp2/t1.c. Remote attackers
could leverage this vulnerability to cause a denial of service
via a crafted bmp file. This issue is similar to CVE-2018-6616.

CVE-2020-6851

OpenJPEG through 2.3.1 has a heap-based buffer overflow in
opj_t1_clbl_decode_processor in openjp2/t1.c because of lack
of opj_j2k_update_image_dimensions validation.

CVE-2020-8112

opj_t1_clbl_decode_processor in openjp2/t1.c in OpenJPEG 2.3.1
through 2020-01-28 has a heap-based buffer overflow in the
qmfbid==1 case, a different issue than CVE-2020-6851.

CVE-2020-15389

jp2/opj_decompress.c in OpenJPEG through 2.3.1 has a
use-after-free that can be triggered if there is a mix of
valid and invalid files in a directory operated on by the
decompressor. Triggering a double-free may also be possible.
This is related to calling opj_image_destroy twice.");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.1.2-1.1+deb9u5.

We recommend that you upgrade your openjpeg2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7-dbg", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-7-dev", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenjp2-tools", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d-tools", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenjp3d7", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-dec-server", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-server", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenjpip-viewer", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenjpip7", ver:"2.1.2-1.1+deb9u5", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
