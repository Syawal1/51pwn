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
  script_oid("1.3.6.1.4.1.25623.1.0.892412");
  script_version("2020-10-31T04:00:15+0000");
  script_cve_id("CVE-2020-14779", "CVE-2020-14781", "CVE-2020-14782", "CVE-2020-14792", "CVE-2020-14796", "CVE-2020-14797", "CVE-2020-14798", "CVE-2020-14803");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-10-31 04:00:15 +0000 (Sat, 31 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-31 04:00:15 +0000 (Sat, 31 Oct 2020)");
  script_name("Debian LTS: Security Advisory for openjdk-8 (DLA-2412-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00031.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2412-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the DLA-2412-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the OpenJDK Java runtime,
resulting in denial of service, bypass of sandbox restrictions or
information disclosure.");

  script_tag(name:"affected", value:"'openjdk-8' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
8u272-b10-0+deb9u1.

We recommend that you upgrade your openjdk-8 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-dbg", ver:"8u272-b10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-demo", ver:"8u272-b10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-doc", ver:"8u272-b10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u272-b10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk-headless", ver:"8u272-b10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u272-b10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u272-b10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u272-b10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-source", ver:"8u272-b10-0+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
