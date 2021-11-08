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
  script_oid("1.3.6.1.4.1.25623.1.0.891305");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2018-5251", "CVE-2018-5294", "CVE-2018-6315", "CVE-2018-6359");
  script_name("Debian LTS: Security Advisory for ming (DLA-1305-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00008.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"ming on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
0.4.4-1.1+deb7u7.

We recommend that you upgrade your ming packages.");

  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in Ming:

CVE-2018-5251

Integer signedness error vulnerability (left shift of a negative value) in
the readSBits function (util/read.c). Remote attackers can leverage this
vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-5294

Integer overflow vulnerability (caused by an out-of-range left shift) in
the readUInt32 function (util/read.c). Remote attackers could leverage this
vulnerability to cause a denial-of-service via a crafted swf file.

CVE-2018-6315

Integer overflow and resultant out-of-bounds read in the
outputSWF_TEXT_RECORD function (util/outputscript.c). Remote attackers
could leverage this vulnerability to cause a denial of service or
unspecified other impact via a crafted SWF file.

CVE-2018-6359

Use-after-free vulnerability in the decompileIF function
(util/decompile.c). Remote attackers could leverage this vulnerability to
cause a denial of service or unspecified other impact via a crafted SWF
file.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libming-dev", ver:"0.4.4-1.1+deb7u7", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libming-util", ver:"0.4.4-1.1+deb7u7", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libming1", ver:"0.4.4-1.1+deb7u7", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswf-perl", ver:"0.4.4-1.1+deb7u7", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ming-fonts-dejavu", ver:"0.4.4-1.1+deb7u7", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ming-fonts-opensymbol", ver:"0.4.4-1.1+deb7u7", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"php5-ming", ver:"0.4.4-1.1+deb7u7", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-ming", ver:"0.4.4-1.1+deb7u7", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
