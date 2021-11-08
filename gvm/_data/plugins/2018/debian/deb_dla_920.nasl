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
  script_oid("1.3.6.1.4.1.25623.1.0.890920");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2016-10251", "CVE-2016-9591");
  script_name("Debian LTS: Security Advisory for jasper (DLA-920-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00039.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"jasper on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.900.1-13+deb7u6.

We recommend that you upgrade your jasper packages.");

  script_tag(name:"summary", value:"CVE-2016-9591
Use-after-free on heap in jas_matrix_destroy
The vulnerability exists in code responsible for re-encoding the
decoded input image file to a JP2 image. The vulnerability is
caused by not setting related pointers to be null after the
pointers are freed (i.e. missing Setting-Pointer-Null operations
after free). The vulnerability can further cause double-free.

CVE-2016-10251
Integer overflow in the jpc_pi_nextcprl function in jpc_t2cod.c in
JasPer before 1.900.20 allows remote attackers to have unspecified
impact via a crafted file, which triggers use of an uninitialized
value.

Additional
fix for TEMP-CVE from last upload to avoid hassle with SIZE_MAX");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-13+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-13+deb7u6", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjasper1", ver:"1.900.1-13+deb7u6", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
