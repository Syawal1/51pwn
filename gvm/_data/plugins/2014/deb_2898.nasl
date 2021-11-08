# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2898-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702898");
  script_version("2020-02-25T10:11:08+0000");
  script_cve_id("CVE-2014-1947", "CVE-2014-1958", "CVE-2014-2030");
  script_name("Debian Security Advisory DSA 2898-1 (imagemagick - security update)");
  script_tag(name:"last_modification", value:"2020-02-25 10:11:08 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2014-04-09 00:00:00 +0200 (Wed, 09 Apr 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2898.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"imagemagick on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze),
these problems have been fixed in version 8:6.6.0.4-3+squeeze4.

For the stable distribution (wheezy), these problems have been fixed in
version 8:6.7.7.10-5+deb7u3.

For the testing distribution (jessie), these problems have been fixed in
version 8:6.7.7.10+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 8:6.7.7.10+dfsg-1.

We recommend that you upgrade your imagemagick packages.");
  script_tag(name:"summary", value:"Several buffer overflows were found in Imagemagick, a suite of image
manipulation programs. Processing malformed PSD files could lead to the
execution of arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagick++3", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickcore3", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickcore3-extra", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickwand3", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.6.0.4-3+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagick++5", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickcore5", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickcore5-extra", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickwand5", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.7.7.10-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}