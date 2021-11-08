# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891513");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2018-16947", "CVE-2018-16948", "CVE-2018-16949");
  script_name("Debian LTS: Security Advisory for openafs (DLA-1513-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-09-24 00:00:00 +0200 (Mon, 24 Sep 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00024.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"openafs on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.6.9-2+deb8u8.

We recommend that you upgrade your openafs packages.");

  script_tag(name:"summary", value:"Several security vulnerabilities were discovered in OpenAFS, a
distributed file system.

CVE-2018-16947

The backup tape controller process accepts incoming RPCs but does
not require (or allow for) authentication of those RPCs. Handling
those RPCs results in operations being performed with administrator
credentials, including dumping/restoring volume contents and
manipulating the backup database.

CVE-2018-16948

Several RPC server routines did not fully initialize their output
variables before returning, leaking memory contents from both the
stack and the heap. Because the OpenAFS cache manager functions as
an Rx server for the AFSCB service, clients are also susceptible to
information leakage.

CVE-2018-16949

Several data types used as RPC input variables were implemented as
unbounded array types, limited only by the inherent 32-bit length
field to 4GB. An unauthenticated attacker could send, or claim to
send, large input values and consume server resources waiting for
those inputs, denying service to other valid connections.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libafsauthent1", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libafsrpc1", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkopenafs1", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-client", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-dbg", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-doc", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-fuse", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-krb5", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-modules-dkms", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.6.9-2+deb8u8", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
