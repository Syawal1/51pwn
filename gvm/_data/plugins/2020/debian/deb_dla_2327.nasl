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
  script_oid("1.3.6.1.4.1.25623.1.0.892327");
  script_version("2020-08-17T13:22:29+0000");
  script_cve_id("CVE-2019-0193");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-17 13:22:29 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-17 13:22:29 +0000 (Mon, 17 Aug 2020)");
  script_name("Debian LTS: Security Advisory for lucene-solr (DLA-2327-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00025.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2327-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lucene-solr'
  package(s) announced via the DLA-2327-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A security vulnerability was discovered in lucene-solr, an enterprise
search server.

The DataImportHandler, an optional but popular module to pull in data
from databases and other sources, has a feature in which the whole DIH
configuration can come from a request's 'dataConfig' parameter. The
debug mode of the DIH admin screen uses this to allow convenient
debugging / development of a DIH config. Since a DIH config can contain
scripts, this parameter is a security risk. Starting from now on, use
of this parameter requires setting the Java System property
'enable.dih.dataConfigParam' to true. For example this can be achieved
with solr-tomcat by adding -Denable.dih.dataConfigParam=true to
JAVA_OPTS in /etc/default/tomcat8.");

  script_tag(name:"affected", value:"'lucene-solr' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
3.6.2+dfsg-10+deb9u3.

We recommend that you upgrade your lucene-solr packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"liblucene3-contrib-java", ver:"3.6.2+dfsg-10+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblucene3-java", ver:"3.6.2+dfsg-10+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblucene3-java-doc", ver:"3.6.2+dfsg-10+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsolr-java", ver:"3.6.2+dfsg-10+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"solr-common", ver:"3.6.2+dfsg-10+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"solr-jetty", ver:"3.6.2+dfsg-10+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"solr-tomcat", ver:"3.6.2+dfsg-10+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
