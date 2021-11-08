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
  script_oid("1.3.6.1.4.1.25623.1.0.892238");
  script_version("2020-06-15T07:17:09+0000");
  script_cve_id("CVE-2020-13848");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-06-15 07:17:09 +0000 (Mon, 15 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-09 03:00:08 +0000 (Tue, 09 Jun 2020)");
  script_name("Debian LTS: Security Advisory for libupnp (DLA-2238-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2238-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/962282");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libupnp'
  package(s) announced via the DLA-2238-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libupnp, the portable SDK for UPnP Devices allows remote attackers to
cause a denial of service (crash) via a crafted SSDP message due to a
NULL pointer dereference in the functions FindServiceControlURLPath
and FindServiceEventURLPath in genlib/service_table/service_table.c.
This crash can be triggered by sending a malformed SUBSCRIBE or
UNSUBSCRIBE using any of the attached files.");

  script_tag(name:"affected", value:"'libupnp' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
1.6.19+git20141001-1+deb8u2.

We recommend that you upgrade your libupnp packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libupnp-dev", ver:"1.6.19+git20141001-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libupnp6", ver:"1.6.19+git20141001-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libupnp6-dbg", ver:"1.6.19+git20141001-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libupnp6-dev", ver:"1.6.19+git20141001-1+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libupnp6-doc", ver:"1.6.19+git20141001-1+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
