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
  script_oid("1.3.6.1.4.1.25623.1.0.892031");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2019-12211", "CVE-2019-12213");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-12-11 03:00:40 +0000 (Wed, 11 Dec 2019)");
  script_name("Debian LTS: Security Advisory for freeimage (DLA-2031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/12/msg00012.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2031-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/929597");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeimage'
  package(s) announced via the DLA-2031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that freeimage, a graphics library, was affected by the following
two security issues:

CVE-2019-12211

Heap buffer overflow caused by invalid memcpy in PluginTIFF. This flaw
might be leveraged by remote attackers to trigger denial of service or any
other unspecified impact via crafted TIFF data.

CVE-2019-12213

Stack exhaustion caused by unwanted recursion in PluginTIFF. This flaw
might be leveraged by remote attackers to trigger denial of service via
crafted TIFF data.");

  script_tag(name:"affected", value:"'freeimage' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.15.4-4.2+deb8u2.

We recommend that you upgrade your freeimage packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libfreeimage-dev", ver:"3.15.4-4.2+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3", ver:"3.15.4-4.2+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3-dbg", ver:"3.15.4-4.2+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
