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
  script_oid("1.3.6.1.4.1.25623.1.0.892383");
  script_version("2020-09-28T09:02:05+0000");
  script_cve_id("CVE-2019-1010057", "CVE-2019-14459");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-28 09:02:05 +0000 (Mon, 28 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-27 03:00:27 +0000 (Sun, 27 Sep 2020)");
  script_name("Debian LTS: Security Advisory for nfdump (DLA-2383-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00021.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2383-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfdump'
  package(s) announced via the DLA-2383-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two issues have been found in nfdump, a netflow capture daemon.
Both issues are related to either a buffer overflow or an integer
overflow, which could result in a denial of service or a local code
execution.");

  script_tag(name:"affected", value:"'nfdump' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.6.15-3+deb9u1.

We recommend that you upgrade your nfdump packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"nfdump", ver:"1.6.15-3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nfdump-dbg", ver:"1.6.15-3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nfdump-flow-tools", ver:"1.6.15-3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nfdump-sflow", ver:"1.6.15-3+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
