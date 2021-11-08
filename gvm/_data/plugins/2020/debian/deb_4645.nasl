# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704645");
  script_version("2020-03-27T07:20:35+0000");
  script_cve_id("CVE-2019-20503", "CVE-2020-6422", "CVE-2020-6424", "CVE-2020-6425", "CVE-2020-6426", "CVE-2020-6427", "CVE-2020-6428", "CVE-2020-6429", "CVE-2020-6449");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-27 07:20:35 +0000 (Fri, 27 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-24 04:00:17 +0000 (Tue, 24 Mar 2020)");
  script_name("Debian: Security Advisory for chromium (DSA-4645-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4645.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4645-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4645-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2019-20503
Natalie Silvanovich discovered an out-of-bounds read issue in the usrsctp
library.

CVE-2020-6422
David Manouchehri discovered a use-after-free issue in the WebGL
implementation.

CVE-2020-6424
Sergei Glazunov discovered a use-after-free issue.

CVE-2020-6425
Sergei Glazunov discovered a policy enforcement error related to
extensions.

CVE-2020-6426
Avihay Cohen discovered an implementation error in the v8 javascript
library.

CVE-2020-6427
Man Yue Mo discovered a use-after-free issue in the audio implementation.

CVE-2020-6428
Man Yue Mo discovered a use-after-free issue in the audio implementation.

CVE-2020-6429
Man Yue Mo discovered a use-after-free issue in the audio implementation.

CVE-2020-6449
Man Yue Mo discovered a use-after-free issue in the audio implementation.");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), security support for chromium has
been discontinued.

For the stable distribution (buster), these problems have been fixed in
version 80.0.3987.149-1~deb10u1.

We recommend that you upgrade your chromium packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"80.0.3987.149-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
