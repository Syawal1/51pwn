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
  script_oid("1.3.6.1.4.1.25623.1.0.704681");
  script_version("2020-05-09T03:00:15+0000");
  script_cve_id("CVE-2020-3885", "CVE-2020-3894", "CVE-2020-3895", "CVE-2020-3897", "CVE-2020-3899", "CVE-2020-3900", "CVE-2020-3901", "CVE-2020-3902");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-05-09 03:00:15 +0000 (Sat, 09 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-09 03:00:15 +0000 (Sat, 09 May 2020)");
  script_name("Debian: Security Advisory for webkit2gtk (DSA-4681-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4681.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4681-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk'
  package(s) announced via the DSA-4681-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerability has been discovered in the webkit2gtk web
engine:

CVE-2020-3885
Ryan Pickren discovered that a file URL may be incorrectly
processed.

CVE-2020-3894
Sergei Glazunov discovered that a race condition may allow an
application to read restricted memory.

CVE-2020-3895
grigoritchy discovered that processing maliciously crafted web
content may lead to arbitrary code execution.

CVE-2020-3897
Brendan Draper discovered that a remote attacker may be able to
cause arbitrary code execution.

CVE-2020-3899
OSS-Fuzz discovered that a remote attacker may be able to cause
arbitrary code execution.

CVE-2020-3900
Dongzhuo Zhao discovered that processing maliciously crafted web
content may lead to arbitrary code execution.

CVE-2020-3901
Benjamin Randazzo discovered that processing maliciously crafted
web content may lead to arbitrary code execution.

CVE-2020-3902
Yigit Can Yilmaz discovered that processing maliciously crafted
web content may lead to a cross site scripting attack.");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 2.28.2-2~deb10u1.

We recommend that you upgrade your webkit2gtk packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-javascriptcoregtk-4.0", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-webkit2-4.0", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-bin", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-dev", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37-gtk2", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-dev", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-doc", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"webkit2gtk-driver", ver:"2.28.2-2~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
