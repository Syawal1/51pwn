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
  script_oid("1.3.6.1.4.1.25623.1.0.892378");
  script_version("2020-09-28T08:10:21+0000");
  script_cve_id("CVE-2020-1968");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-09-28 08:10:21 +0000 (Mon, 28 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-26 03:00:08 +0000 (Sat, 26 Sep 2020)");
  script_name("Debian LTS: Security Advisory for openssl1.0 (DLA-2378-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00016.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2378-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl1.0'
  package(s) announced via the DLA-2378-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Robert Merget, Marcus Brinkmann, Nimrod Aviram, and Juraj Somorovsky
discovered that certain Diffie-Hellman ciphersuites in the TLS
specification and implemented by OpenSSL contained a flaw. A remote
attacker could possibly use this issue to eavesdrop on encrypted
communications. This was fixed in this update by disabling the insecure
ciphersuites.");

  script_tag(name:"affected", value:"'openssl1.0' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
1.0.2u-1~deb9u2.

We recommend that you upgrade your openssl1.0 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.0.2-udeb", ver:"1.0.2u-1~deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl1.0-dev", ver:"1.0.2u-1~deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.2", ver:"1.0.2u-1~deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.2-udeb", ver:"1.0.2u-1~deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
