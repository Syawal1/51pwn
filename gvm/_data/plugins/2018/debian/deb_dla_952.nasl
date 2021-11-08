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
  script_oid("1.3.6.1.4.1.25623.1.0.890952");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2013-2074", "CVE-2017-6410", "CVE-2017-8422");
  script_name("Debian LTS: Security Advisory for kde4libs (DLA-952-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-01-25 00:00:00 +0100 (Thu, 25 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00023.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"kde4libs on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
4:4.8.4-4+deb7u3.

We recommend that you upgrade your kde4libs packages.");

  script_tag(name:"summary", value:"Several vulnerabilities were discovered in kde4libs, the core libraries
for all KDE 4 applications. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2017-6410

Itzik Kotler, Yonatan Fridburg and Amit Klein of Safebreach Labs
reported that URLs are not sanitized before passing them to
FindProxyForURL, potentially allowing a remote attacker to obtain
sensitive information via a crafted PAC file.

CVE-2017-8422

Sebastian Krahmer from SUSE discovered that the KAuth framework
contains a logic flaw in which the service invoking dbus is not
properly checked. This flaw allows spoofing the identity of the
caller and gaining root privileges from an unprivileged account.

CVE-2013-2074

It was discovered that KIO would show web authentication
credentials in some error cases.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"kdelibs-bin", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kdelibs5-data", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kdelibs5-dbg", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kdelibs5-dev", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kdelibs5-plugins", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kdoctools", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkcmutils4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkde3support4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdeclarative5", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdecore5", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdesu5", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdeui5", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdewebkit5", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdnssd4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkemoticons4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkfile4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkhtml5", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkidletime4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkimproxy4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkio5", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkjsapi4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkjsembed4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkmediaplayer4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libknewstuff2-4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libknewstuff3-4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libknotifyconfig4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkntlm4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkparts4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkprintutils4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkpty4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrosscore4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrossui4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libktexteditor4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkunitconversion4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkutils4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnepomuk4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnepomukquery4a", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnepomukutils4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libplasma3", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsolid4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libthreadweaver4", ver:"4:4.8.4-4+deb7u3", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
