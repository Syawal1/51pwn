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
  script_oid("1.3.6.1.4.1.25623.1.0.704513");
  script_version("2019-09-10T07:33:37+0000");
  script_cve_id("CVE-2019-10197");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-09-10 07:33:37 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-05 02:00:07 +0000 (Thu, 05 Sep 2019)");
  script_name("Debian Security Advisory DSA 4513-1 (samba - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4513.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4513-1");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2019-10197.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the DSA-4513-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Metzmacher discovered a flaw in Samba, a SMB/CIFS file, print,
and login server for Unix. Specific combinations of parameters and
permissions can allow user to escape from the share path definition and
see the complete '/' filesystem. Unix permission checks in the kernel
are still enforced.

Details can be found in the upstream advisory linked in the references.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), this problem has been fixed in
version 2:4.9.5+dfsg-5+deb10u1.

We recommend that you upgrade your samba packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ctdb", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnss-winbind", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpam-winbind", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libparse-pidl-perl", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwbclient0", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-samba", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-libs", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"2:4.9.5+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
