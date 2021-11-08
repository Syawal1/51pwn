# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704596");
  script_version("2019-12-29T03:00:16+0000");
  script_cve_id("CVE-2018-11784", "CVE-2018-8014", "CVE-2019-0199", "CVE-2019-0221", "CVE-2019-12418", "CVE-2019-17563");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-12-29 03:00:16 +0000 (Sun, 29 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-29 03:00:16 +0000 (Sun, 29 Dec 2019)");
  script_name("Debian Security Advisory DSA 4596-1 (tomcat8 - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4596.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4596-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat8'
  package(s) announced via the DSA-4596-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues were discovered in the Tomcat servlet and JSP engine, which
could result in session fixation attacks, information disclosure, cross-site
scripting, denial of service via resource exhaustion and insecure
redirects.");

  script_tag(name:"affected", value:"'tomcat8' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), these problems have been fixed
in version 8.5.50-0+deb9u1. This update also requires an updated version
of tomcat-native which has been updated to 1.2.21-1~deb9u1.

We recommend that you upgrade your tomcat8 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.1-java", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.1-java-doc", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-embed-java", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-admin", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-common", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-docs", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-examples", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-user", ver:"8.5.50-0+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);