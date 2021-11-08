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
  script_oid("1.3.6.1.4.1.25623.1.0.892249");
  script_version("2020-07-09T09:54:34+0000");
  script_cve_id("CVE-2020-0182", "CVE-2020-0198");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-07-09 09:54:34 +0000 (Thu, 09 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-14 03:00:24 +0000 (Sun, 14 Jun 2020)");
  script_name("Debian LTS: Security Advisory for libexif (DLA-2249-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2249-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/962345");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libexif'
  package(s) announced via the DLA-2249-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following CVE(s) were reported against src:libexif.

CVE-2020-0182

In exif_entry_get_value of exif-entry.c, there is a possible
out of bounds read due to a missing bounds check. This could
lead to local information disclosure with no additional execution
privileges needed. User interaction is not needed for
exploitation.

CVE-2020-0198

In exif_data_load_data_content of exif-data.c, there is a
possible UBSAN abort due to an integer overflow. This could lead
to remote denial of service with no additional execution
privileges needed. User interaction is needed for exploitation.");

  script_tag(name:"affected", value:"'libexif' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.6.21-2+deb8u4.

We recommend that you upgrade your libexif packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libexif-dev", ver:"0.6.21-2+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libexif12", ver:"0.6.21-2+deb8u4", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
