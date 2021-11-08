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
  script_oid("1.3.6.1.4.1.25623.1.0.891282");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2018-6799");
  script_name("Debian LTS: Security Advisory for graphicsmagick (DLA-1282-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-02-21 00:00:00 +0100 (Wed, 21 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/02/msg00017.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"graphicsmagick on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.3.16-1.1+deb7u18.

We recommend that you upgrade your graphicsmagick packages.");

  script_tag(name:"summary", value:"A denial of service vulnerability has been discovered in graphicsmagick,
a collection of image processing tools and associated libraries.

A specially crafted file can be used to produce a denial of service
(heap overwrite) or possible other unspecified impact by exploiting a
defect related to unused pixel staging area in the AcquireCacheNexus
function in magick/pixel_cache.c.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.16-1.1+deb7u18", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.3.16-1.1+deb7u18", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.3.16-1.1+deb7u18", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.3.16-1.1+deb7u18", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.3.16-1.1+deb7u18", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.3.16-1.1+deb7u18", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++3", ver:"1.3.16-1.1+deb7u18", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.3.16-1.1+deb7u18", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick3", ver:"1.3.16-1.1+deb7u18", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}