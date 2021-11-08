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
  script_oid("1.3.6.1.4.1.25623.1.0.704727");
  script_version("2020-07-19T03:00:13+0000");
  script_cve_id("CVE-2020-11996", "CVE-2020-13934", "CVE-2020-13935", "CVE-2020-9484");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-07-19 03:00:13 +0000 (Sun, 19 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-19 03:00:13 +0000 (Sun, 19 Jul 2020)");
  script_name("Debian: Security Advisory for tomcat9 (DSA-4727-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4727.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4727-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat9'
  package(s) announced via the DSA-4727-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Tomcat servlet and JSP
engine, which could result in code execution or denial of service.");

  script_tag(name:"affected", value:"'tomcat9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 9.0.31-1~deb10u2.

We recommend that you upgrade your tomcat9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-embed-java", ver:"9.0.31-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.31-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.31-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-admin", ver:"9.0.31-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-common", ver:"9.0.31-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-docs", ver:"9.0.31-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-examples", ver:"9.0.31-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-user", ver:"9.0.31-1~deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
