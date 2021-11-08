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
  script_oid("1.3.6.1.4.1.25623.1.0.892286");
  script_version("2020-07-23T03:00:20+0000");
  script_cve_id("CVE-2020-13934", "CVE-2020-13935");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-07-23 03:00:20 +0000 (Thu, 23 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-23 03:00:20 +0000 (Thu, 23 Jul 2020)");
  script_name("Debian LTS: Security Advisory for tomcat8 (DLA-2286-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2286-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat8'
  package(s) announced via the DLA-2286-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine.

CVE-2020-13934

An h2c direct connection to Apache Tomcat did not release the
HTTP/1.1 processor after the upgrade to HTTP/2. If a sufficient
number of such requests were made, an OutOfMemoryException could
occur leading to a denial of service.

CVE-2020-13935

The payload length in a WebSocket frame was not correctly validated
in Apache Tomcat. Invalid payload lengths could trigger an infinite
loop. Multiple requests with invalid payload lengths could lead to a
denial of service.");

  script_tag(name:"affected", value:"'tomcat8' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
8.5.54-0+deb9u3.

We recommend that you upgrade your tomcat8 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.1-java", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.1-java-doc", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-embed-java", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-admin", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-common", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-docs", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-examples", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-user", ver:"8.5.54-0+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
