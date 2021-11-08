# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2658-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.702658");
  script_version("2020-10-05T06:02:24+0000");
  script_cve_id("CVE-2013-1900", "CVE-2013-1899", "CVE-2013-1901");
  script_name("Debian Security Advisory DSA 2658-1 (postgresql-9.1 - several vulnerabilities)");
  script_tag(name:"last_modification", value:"2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-04-04 00:00:00 +0200 (Thu, 04 Apr 2013)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2658.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"postgresql-9.1 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), postgresql-9.1 is not available.
DSA-2657-1 has been released for CVE-2013-1900

affecting posgresql-8.4.

For the testing distribution (wheezy), these problems have been fixed in
version 9.1.9-0wheezy1.

For the unstable distribution (sid), these problems have been fixed in
version 9.1.9-1.

We recommend that you upgrade your postgresql-9.1 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in PostgreSQL database server.

CVE-2013-1899Mitsumasa Kondo and Kyotaro Horiguchi of NTT Open Source Software Center
discovered that it was possible for a connection request containing a
database name that begins with -
to be crafted that can damage or
destroy files within a server's data directory. Anyone with access to the
port the PostgreSQL server listens on can initiate this request.

CVE-2013-1900
Random numbers generated by contrib/pgcrypto functions may be easy for
another database user to guess.

CVE-2013-1901
An unprivileged user could run commands that could interfere with
in-progress backups.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecpg6", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpq-dev", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpq5", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-9.1-dbg", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-client-9.1", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-contrib-9.1", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-doc-9.1", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plperl-9.1", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plpython-9.1", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plpython3-9.1", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-pltcl-9.1", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-server-dev-9.1", ver:"9.1.9-0wheezy1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
