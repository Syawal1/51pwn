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
  script_oid("1.3.6.1.4.1.25623.1.0.892056");
  script_version("2020-11-06T07:45:42+0000");
  script_cve_id("CVE-2019-16789");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-11-06 07:45:42 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-01-02 03:00:08 +0000 (Thu, 02 Jan 2020)");
  script_name("Debian LTS: Security Advisory for waitress (DLA-2056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00002.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2056-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/765126");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'waitress'
  package(s) announced via the DLA-2056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a HTTP request smuggling
vulnerability in waitress, pure-Python WSGI server.

If a proxy server is used in front of waitress, an invalid request
may be sent by an attacker that bypasses the front-end and is parsed
differently by waitress leading to a potential for request smuggling.

Specially crafted requests containing special whitespace characters
in the Transfer-Encoding header would get parsed by Waitress as being
a chunked request, but a front-end server would use the
Content-Length instead as the Transfer-Encoding header is considered
invalid due to containing invalid characters. If a front-end server
does HTTP pipelining to a backend Waitress server this could lead to
HTTP request splitting which may lead to potential cache poisoning or
information disclosure.");

  script_tag(name:"affected", value:"'waitress' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this issue has been fixed in waitress version
0.8.9-2+deb8u1.

We recommend that you upgrade your waitress packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-waitress", ver:"0.8.9-2+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-waitress-doc", ver:"0.8.9-2+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-waitress", ver:"0.8.9-2+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
