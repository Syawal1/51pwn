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
  script_oid("1.3.6.1.4.1.25623.1.0.704611");
  script_version("2020-02-04T09:04:16+0000");
  script_cve_id("CVE-2020-7247");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-02-04 09:04:16 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-01-31 04:00:05 +0000 (Fri, 31 Jan 2020)");
  script_name("Debian: Security Advisory for opensmtpd (DSA-4611-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4611.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4611-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensmtpd'
  package(s) announced via the DSA-4611-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qualys discovered that the OpenSMTPD SMTP server performed insufficient
validation of email addresses which could result in the execution of
arbitrary commands as root. In addition this update fixes a denial of
service by triggering an opportunistic TLS downgrade.");

  script_tag(name:"affected", value:"'opensmtpd' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), these problems have been fixed
in version 6.0.2p1-2+deb9u2.

For the stable distribution (buster), these problems have been fixed in
version 6.0.3p1-5+deb10u3. This update also includes non-security
bugfixes which were already lined up for the Buster 10.3 point release.

We recommend that you upgrade your opensmtpd packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"opensmtpd", ver:"6.0.3p1-5+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"opensmtpd", ver:"6.0.2p1-2+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
