# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2746-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702746");
  script_version("2020-10-05T06:02:24+0000");
  script_cve_id("CVE-2013-1701", "CVE-2013-1710", "CVE-2013-1717", "CVE-2013-1714", "CVE-2013-1709", "CVE-2013-1713");
  script_name("Debian Security Advisory DSA 2746-1 (icedove - several vulnerabilities)");
  script_tag(name:"last_modification", value:"2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-08-29 00:00:00 +0200 (Thu, 29 Aug 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2746.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"icedove on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 17.0.8-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 17.0.8-1.

We recommend that you upgrade your icedove packages.");
  script_tag(name:"summary", value:"Multiple security issues have been found in Icedove, Debian's version of
the Mozilla Thunderbird mail and news client. Multiple memory safety
errors, missing permission checks and other implementation errors may
lead to the execution of arbitrary code or cross-site scripting.

The Icedove version in the oldstable distribution (squeeze) is no longer
supported with full security updates. However, it should be noted that
almost all security issues in Icedove stem from the included browser engine.
These security problems only affect Icedove if scripting and HTML mails
are enabled. If there are security issues specific to Icedove (e.g. a
hypothetical buffer overflow in the IMAP implementation) we'll make an
effort to backport such fixes to oldstable.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"calendar-google-provider", ver:"17.0.8-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"calendar-timezones", ver:"17.0.8-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove", ver:"17.0.8-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dbg", ver:"17.0.8-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dev", ver:"17.0.8-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceowl-extension", ver:"17.0.8-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
