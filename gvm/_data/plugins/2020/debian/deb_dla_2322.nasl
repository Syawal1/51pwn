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
  script_oid("1.3.6.1.4.1.25623.1.0.892322");
  script_version("2020-08-17T13:22:04+0000");
  script_cve_id("CVE-2020-16145");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-17 13:22:04 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-17 13:22:04 +0000 (Mon, 17 Aug 2020)");
  script_name("Debian LTS: Security Advisory for roundcube (DLA-2322-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00018.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2322-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/968216");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcube'
  package(s) announced via the DLA-2322-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in roundcube, a skinnable AJAX based
webmail solution for IMAP servers. HTML messages with malicious svg or
math content can exploit a Cross-site scripting (XSS) vulnerability.");

  script_tag(name:"affected", value:"'roundcube' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
1.2.3+dfsg.1-4+deb9u7.

We recommend that you upgrade your roundcube packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.2.3+dfsg.1-4+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.2.3+dfsg.1-4+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-mysql", ver:"1.2.3+dfsg.1-4+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-pgsql", ver:"1.2.3+dfsg.1-4+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-plugins", ver:"1.2.3+dfsg.1-4+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"roundcube-sqlite3", ver:"1.2.3+dfsg.1-4+deb9u7", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
