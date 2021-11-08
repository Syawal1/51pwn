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
  script_oid("1.3.6.1.4.1.25623.1.0.891121");
  script_version("2020-11-12T10:09:08+0000");
  script_cve_id("CVE-2017-1000254");
  script_name("Debian LTS: Security Advisory for curl (DLA-1121-1)");
  script_tag(name:"last_modification", value:"2020-11-12 10:09:08 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/10/msg00001.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"curl on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', this issue has been fixed in curl version
7.26.0-1+wheezy21.

We recommend that you upgrade your curl packages.");

  script_tag(name:"summary", value:"It was discovered that there was an out-of-bounds read vulnerability in
curl, a command-line and library for transferring data over HTTP/FTP,
etc. A malicious FTP server could abuse this to prevent curl-based
clients from interacting with it.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.26.0-1+wheezy21", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.26.0-1+wheezy21", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.26.0-1+wheezy21", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.26.0-1+wheezy21", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.26.0-1+wheezy21", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.26.0-1+wheezy21", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.26.0-1+wheezy21", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.26.0-1+wheezy21", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
