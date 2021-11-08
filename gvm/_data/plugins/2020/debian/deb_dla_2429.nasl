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
  script_oid("1.3.6.1.4.1.25623.1.0.892429");
  script_version("2020-11-04T04:00:14+0000");
  script_cve_id("CVE-2020-28032", "CVE-2020-28033", "CVE-2020-28034", "CVE-2020-28035", "CVE-2020-28036", "CVE-2020-28037", "CVE-2020-28038", "CVE-2020-28039", "CVE-2020-28040");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-04 04:00:14 +0000 (Wed, 04 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-04 04:00:14 +0000 (Wed, 04 Nov 2020)");
  script_name("Debian LTS: Security Advisory for wordpress (DLA-2429-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00004.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2429-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/973562");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wordpress'
  package(s) announced via the DLA-2429-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There were several vulnerabilities reported against wordpress,
as follows:

CVE-2020-28032

WordPress before 4.7.19 mishandles deserialization requests in
wp-includes/Requests/Utility/FilteredIterator.php.

CVE-2020-28033

WordPress before 4.7.19 mishandles embeds from disabled sites
on a multisite network, as demonstrated by allowing a spam
embed.

CVE-2020-28034

WordPress before 4.7.19 allows XSS associated with global
variables.

CVE-2020-28035

WordPress before 4.7.19 allows attackers to gain privileges via
XML-RPC.

CVE-2020-28036

wp-includes/class-wp-xmlrpc-server.php in WordPress before
4.7.19 allows attackers to gain privileges by using XML-RPC to
comment on a post.

CVE-2020-28037

is_blog_installed in wp-includes/functions.php in WordPress
before 4.7.19 improperly determines whether WordPress is
already installed, which might allow an attacker to perform
a new installation, leading to remote code execution (as well
as a denial of service for the old installation).

CVE-2020-28038

WordPress before 4.7.19 allows stored XSS via post slugs.

CVE-2020-28039

is_protected_meta in wp-includes/meta.php in WordPress before
4.7.19 allows arbitrary file deletion because it does not
properly determine whether a meta key is considered protected.

CVE-2020-28040

WordPress before 4.7.19 allows CSRF attacks that change a
theme's background image.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.7.19+dfsg-1+deb9u1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"4.7.19+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"4.7.19+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfifteen", ver:"4.7.19+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyseventeen", ver:"4.7.19+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentysixteen", ver:"4.7.19+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
