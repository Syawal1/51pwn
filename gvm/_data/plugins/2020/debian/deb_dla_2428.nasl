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
  script_oid("1.3.6.1.4.1.25623.1.0.892428");
  script_version("2020-11-09T07:42:12+0000");
  script_cve_id("CVE-2020-14355");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-09 07:42:12 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-03 04:00:18 +0000 (Tue, 03 Nov 2020)");
  script_name("Debian LTS: Security Advisory for spice-gtk (DLA-2428-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00002.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2428-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/971751");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-gtk'
  package(s) announced via the DLA-2428-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple buffer overflow vulnerabilities were found in the QUIC
image decoding process of the SPICE remote display system.

Both the SPICE client (spice-gtk) and server are affected by
these flaws. These flaws allow a malicious client or server to
send specially crafted messages that, when processed by the
QUIC image compression algorithm, result in a process crash or
potential code execution.");

  script_tag(name:"affected", value:"'spice-gtk' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
0.33-3.3+deb9u2.

We recommend that you upgrade your spice-gtk packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-spice-client-glib-2.0", ver:"0.33-3.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-spice-client-gtk-3.0", ver:"0.33-3.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-glib-2.0-8", ver:"0.33-3.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-glib-2.0-dev", ver:"0.33-3.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-gtk-3.0-5", ver:"0.33-3.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-gtk-3.0-dev", ver:"0.33-3.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"spice-client-glib-usb-acl-helper", ver:"0.33-3.3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"spice-client-gtk", ver:"0.33-3.3+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
