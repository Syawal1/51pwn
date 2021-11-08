# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2783-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702783");
  script_version("2020-10-05T06:02:24+0000");
  script_cve_id("CVE-2011-5036", "CVE-2013-0183", "CVE-2013-0184", "CVE-2013-0263");
  script_name("Debian Security Advisory DSA 2783-1 (librack-ruby - several vulnerabilities)");
  script_tag(name:"last_modification", value:"2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-10-21 00:00:00 +0200 (Mon, 21 Oct 2013)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2783.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_tag(name:"affected", value:"librack-ruby on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 1.1.0-4+squeeze1.

The stable, testing and unstable distributions do not contain the
librack-ruby package. They have already been addressed in version
1.4.1-2.1 of the ruby-rack package.

We recommend that you upgrade your librack-ruby packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in Rack, a modular Ruby
webserver interface. The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:

CVE-2011-5036
Rack computes hash values for form parameters without restricting
the ability to trigger hash collisions predictably, which allows
remote attackers to cause a denial of service (CPU consumption)
by sending many crafted parameters.

CVE-2013-0183
A remote attacker could cause a denial of service (memory
consumption and out-of-memory error) via a long string in a
Multipart HTTP packet.

CVE-2013-0184
A vulnerability in Rack::Auth::AbstractRequest allows remote
attackers to cause a denial of service via unknown vectors.

CVE-2013-0263
Rack::Session::Cookie allows remote attackers to guess the
session cookie, gain privileges, and execute arbitrary code via a
timing attack involving an HMAC comparison function that does not
run in constant time.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"librack-ruby", ver:"1.1.0-4+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"librack-ruby1.8", ver:"1.1.0-4+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"librack-ruby1.9.1", ver:"1.1.0-4+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
