# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891052");
  script_version("2020-11-12T09:50:32+0000");
  script_cve_id("CVE-2017-9800");
  script_name("Debian LTS: Security Advisory for subversion (DLA-1052-1)");
  script_tag(name:"last_modification", value:"2020-11-12 09:50:32 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/08/msg00004.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"subversion on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', this issue has been fixed in subversion
version 1.6.17dfsg-4+deb7u12.

We recommend that you upgrade your subversion packages.");

  script_tag(name:"summary", value:"It was discovered that there was an arbitrary code execution
vulnerability in the subversion revision control system via
malicious 'svn+ssh' URLs in 'svn:externals' and
'svn:sync-from-url'.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-java", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-subversion", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"subversion", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"subversion-tools", ver:"1.6.17dfsg-4+deb7u12", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
