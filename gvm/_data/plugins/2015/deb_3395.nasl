# OpenVAS Vulnerability Test
# $Id: deb_3395.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3395-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.703395");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-2695", "CVE-2015-2696", "CVE-2015-2697");
  script_name("Debian Security Advisory DSA 3395-1 (krb5 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-11-06 00:00:00 +0100 (Fri, 06 Nov 2015)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3395.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|9|8)");
  script_tag(name:"affected", value:"krb5 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 1.10.1+dfsg-5+deb7u4.

For the stable distribution (jessie), these problems have been fixed in
version 1.12.1+dfsg-19+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 1.13.2+dfsg-3.

For the unstable distribution (sid), these problems have been fixed in
version 1.13.2+dfsg-3.

We recommend that you upgrade your krb5 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were
discovered in krb5, the MIT implementation of Kerberos. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-2695
It was discovered that applications which call gss_inquire_context()
on a partially-established SPNEGO context can cause the GSS-API
library to read from a pointer using the wrong type, leading to a
process crash.

CVE-2015-2696
It was discovered that applications which call gss_inquire_context()
on a partially-established IAKERB context can cause the GSS-API
library to read from a pointer using the wrong type, leading to a
process crash.

CVE-2015-2697
It was discovered that the build_principal_va() function incorrectly
handles input strings. An authenticated attacker can take advantage
of this flaw to cause a KDC to crash using a TGS request with a
large realm field beginning with a null byte.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-gss-samples", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-locales", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit8:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit8:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit8:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit8:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-6:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-6:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0:amd64", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0:i386", ver:"1.10.1+dfsg-5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-gss-samples", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-k5tls", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-locales", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-otp", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit9", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit9", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-8", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrad-dev", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrad0", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.13.2+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-gss-samples", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-locales", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-otp:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-otp:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit9:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit9:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit9:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit9:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-7:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-7:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrad-dev", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrad0:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrad0:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0:amd64", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0:i386", ver:"1.12.1+dfsg-19+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}