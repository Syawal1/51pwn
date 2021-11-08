# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.892059");
  script_version("2020-02-10T07:58:04+0000");
  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1387");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-02-10 07:58:04 +0000 (Mon, 10 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-01-24 04:00:08 +0000 (Fri, 24 Jan 2020)");
  script_name("Debian LTS: Security Advisory for git (DLA-2059-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00019.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2059-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git'
  package(s) announced via the DLA-2059-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in git, a fast, scalable,
distributed revision control system.

CVE-2019-1348

It was reported that the --export-marks option of git fast-import is
exposed also via the in-stream command feature export-marks=...,
allowing to overwrite arbitrary paths.

CVE-2019-1387

It was discovered that submodule names are not validated strictly
enough, allowing very targeted attacks via remote code execution
when performing recursive clones.

In addition this update addresses a number of security issues which are
only an issue if git is operating on an NTFS filesystem (CVE-2019-1349,
CVE-2019-1352 and CVE-2019-1353).");

  script_tag(name:"affected", value:"'git' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:2.1.4-2.1+deb8u8.

We recommend that you upgrade your git packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"git", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-all", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-arch", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-core", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-cvs", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-run", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-sysvinit", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-doc", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-el", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-email", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-gui", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-man", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-mediawiki", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-svn", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitk", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitweb", ver:"1:2.1.4-2.1+deb8u8", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
