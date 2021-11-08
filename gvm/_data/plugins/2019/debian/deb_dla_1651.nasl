# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891651");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2018-1000222", "CVE-2018-5711", "CVE-2019-6977", "CVE-2019-6978");
  script_name("Debian LTS: Security Advisory for libgd2 (DLA-1651-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-01-31 00:00:00 +0100 (Thu, 31 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00028.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"libgd2 on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.1.0-5+deb8u12.

We recommend that you upgrade your libgd2 packages.");

  script_tag(name:"summary", value:"Several issues in libgd2, a graphics library that allows to quickly draw
images, have been found.

CVE-2019-6977
A potential double free in gdImage*Ptr() has been reported by Solmaz
Salimi (aka. Rooney).

CVE-2019-6978
Simon Scannell found a heap-based buffer overflow, exploitable with
crafted image data.

CVE-2018-1000222
A new double free vulnerabilities in gdImageBmpPtr() has been
reported by Solmaz Salimi (aka. Rooney).

CVE-2018-5711
Due to an integer signedness error the GIF core parsing function can
enter an infinite loop. This will lead to a Denial of Service and
exhausted server resources.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libgd-dbg", ver:"2.1.0-5+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgd-dev", ver:"2.1.0-5+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgd-tools", ver:"2.1.0-5+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgd2-noxpm-dev", ver:"2.1.0-5+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgd2-xpm-dev", ver:"2.1.0-5+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgd3", ver:"2.1.0-5+deb8u12", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
