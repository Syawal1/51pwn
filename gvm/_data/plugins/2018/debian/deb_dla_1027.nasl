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
  script_oid("1.3.6.1.4.1.25623.1.0.891027");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2017-11103");
  script_name("Debian LTS: Security Advisory for heimdal (DLA-1027-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-02-05 00:00:00 +0100 (Mon, 05 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00019.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"heimdal on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.6~git20120403+dfsg1-2+deb7u1.

We recommend that you upgrade your heimdal packages.");

  script_tag(name:"summary", value:"Jeffrey Altman, Viktor Duchovni and Nico Williams identified a mutual
authentication bypass vulnerability in Heimdal Kerberos. Also known as
Orpheus' Lyre, this vulnerability could be used by an attacker to mount
a service impersonation attack on the client if he's on the network
path between the client and the service.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients-x", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-dbg", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-dev", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-docs", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-multidev", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers-x", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhcrypto4-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libheimbase1-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libheimntlm0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt7-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv8-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libroken18-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwind0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
