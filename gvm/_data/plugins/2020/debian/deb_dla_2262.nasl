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
  script_oid("1.3.6.1.4.1.25623.1.0.892262");
  script_version("2020-06-30T03:00:09+0000");
  script_cve_id("CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13765", "CVE-2020-1983");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-06-30 03:00:09 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-30 03:00:09 +0000 (Tue, 30 Jun 2020)");
  script_name("Debian LTS: Security Advisory for qemu (DLA-2262-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00032.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2262-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the DLA-2262-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in qemu,
a fast processor emulator.

CVE-2020-1983

slirp: Fix use-after-free in ip_reass().

CVE-2020-13361

es1370_transfer_audio in hw/audio/es1370.c
allowed guest OS users to trigger an out-of-bounds access
during an es1370_write() operation.

CVE-2020-13362

megasas_lookup_frame in hw/scsi/megasas.c had
an out-of-bounds read via a crafted reply_queue_head field from
a guest OS user.

CVE-2020-13765

hw/core/loader: Fix possible crash in rom_copy().");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:2.1+dfsg-12+deb8u15.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.1+dfsg-12+deb8u15", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
