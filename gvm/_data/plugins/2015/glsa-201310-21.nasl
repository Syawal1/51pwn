###############################################################################
# OpenVAS Vulnerability Test
#
# Gentoo Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (C) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121059");
  script_version("2020-08-04T08:27:56+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:26:14 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)");
  script_name("Gentoo Security Advisory GLSA 201310-21");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in MediaWiki. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201310-21");
  script_cve_id("CVE-2013-1816", "CVE-2013-1817", "CVE-2013-1818", "CVE-2013-1951", "CVE-2013-2031", "CVE-2013-2032", "CVE-2013-2114", "CVE-2013-4301", "CVE-2013-4302", "CVE-2013-4303", "CVE-2013-4304", "CVE-2013-4305", "CVE-2013-4306", "CVE-2013-4307", "CVE-2013-4308");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201310-21");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-apps/mediawiki", unaffected: make_list("ge 1.21.2"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-apps/mediawiki", unaffected: make_list("ge 1.20.7"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-apps/mediawiki", unaffected: make_list("ge 1.19.8"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-apps/mediawiki", unaffected: make_list(), vulnerable: make_list("lt 1.21.2"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
