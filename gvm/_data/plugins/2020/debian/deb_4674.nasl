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
  script_oid("1.3.6.1.4.1.25623.1.0.704674");
  script_version("2020-05-11T07:05:27+0000");
  script_cve_id("CVE-2020-12625", "CVE-2020-12626");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-05-11 07:05:27 +0000 (Mon, 11 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-06 03:00:15 +0000 (Wed, 06 May 2020)");
  script_name("Debian: Security Advisory for roundcube (DSA-4674-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4674.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4674-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcube'
  package(s) announced via the DSA-4674-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that roundcube, a skinnable AJAX based webmail
solution for IMAP servers, did not correctly process and sanitize
requests. This would allow a remote attacker to perform either a
Cross-Site Request Forgery (CSRF) forcing an authenticated user to be
logged out, or a Cross-Side Scripting (XSS) leading to execution of
arbitrary code.");

  script_tag(name:"affected", value:"'roundcube' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), these problems have been fixed
in version 1.2.3+dfsg.1-4+deb9u4.

For the stable distribution (buster), these problems have been fixed in
version 1.3.11+dfsg.1-1~deb10u1.

We recommend that you upgrade your roundcube packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.3.11+dfsg.1-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.3.11+dfsg.1-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-mysql", ver:"1.3.11+dfsg.1-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-pgsql", ver:"1.3.11+dfsg.1-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-plugins", ver:"1.3.11+dfsg.1-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-sqlite3", ver:"1.3.11+dfsg.1-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.2.3+dfsg.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.2.3+dfsg.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-mysql", ver:"1.2.3+dfsg.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-pgsql", ver:"1.2.3+dfsg.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-plugins", ver:"1.2.3+dfsg.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-sqlite3", ver:"1.2.3+dfsg.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);