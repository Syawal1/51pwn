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
  script_oid("1.3.6.1.4.1.25623.1.0.892090");
  script_version("2020-07-21T08:11:15+0000");
  script_cve_id("CVE-2020-7039");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-21 08:11:15 +0000 (Tue, 21 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-01-31 04:00:15 +0000 (Fri, 31 Jan 2020)");
  script_name("Debian LTS: Security Advisory for qemu (DLA-2090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00036.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2090-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/949085");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the DLA-2090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tcp_emu in tcp_subr.c in libslirp 4.1.0, as used in QEMU 4.2.0, mismanag
esmemory, as demonstrated by IRC DCC commands in EMU_IRC.
This can cause a heap-based buffer overflow or other out-of-bounds access
which can lead to a DoS or potential execute arbitrary code.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
1:2.1+dfsg-12+deb8u13.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.1+dfsg-12+deb8u13", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
