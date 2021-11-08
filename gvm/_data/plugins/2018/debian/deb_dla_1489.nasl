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
  script_oid("1.3.6.1.4.1.25623.1.0.891489");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2018-10873");
  script_name("Debian LTS: Security Advisory for spice-gtk (DLA-1489-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-09-03 00:00:00 +0200 (Mon, 03 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00038.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"spice-gtk on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
0.25-1+deb8u1.

We recommend that you upgrade your spice-gtk packages.");

  script_tag(name:"summary", value:'A vulnerability was discovered in SPICE before version 0.14.1 where the
generated code used for demarshalling messages lacked sufficient bounds
checks. A malicious client or server, after authentication, could send
specially crafted messages to its peer which would result in a crash or,
potentially, other impacts.

The issue has been fixed by upstream by bailing out with an error if the
pointer to the start of some message data is strictly greater than the
pointer to the end of the  message data.

The above issue and fix have already been announced for the "spice"
Debian package (as DLA-1486-1 [1]). This announcement is about the
"spice-gtk" Debian package (which ships some copies of code from the
"spice" package, where the fix of this issue had to be applied).

[1] https://lists.debian.org/debian-lts-announce/2018/08/msg00037.html');
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-spice-client-glib-2.0", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-spice-client-gtk-2.0", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-spice-client-gtk-3.0", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-glib-2.0-8", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-glib-2.0-dev", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-gtk-2.0-4", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-gtk-2.0-dev", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-gtk-3.0-4", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspice-client-gtk-3.0-dev", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-spice-client-gtk", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"spice-client-glib-usb-acl-helper", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"spice-client-gtk", ver:"0.25-1+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}