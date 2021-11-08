# Copyright (C) 2016 Eero Volotinen
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.120648");
  script_version("2020-03-13T13:19:50+0000");
  script_tag(name:"creation_date", value:"2016-03-11 07:09:12 +0200 (Fri, 11 Mar 2016)");
  script_tag(name:"last_modification", value:"2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)");
  script_name("Amazon Linux: Security Advisory (ALAS-2016-658)");
  script_tag(name:"insight", value:"A directory traversal vulnerability in RequestUtil.java was discovered which allows remote authenticated users to bypass intended SecurityManager restrictions and list a parent directory via a /.. (slash dot dot) in a pathname used by a web application in a getResource, getResourceAsStream, or getResourcePaths call. (CVE-2015-5174 )The Mapper component processes redirects before considering security constraints and Filters, which allows remote attackers to determine the existence of a directory via a URL that lacks a trailing / (slash) character. (CVE-2015-5345 )It was found that the expression language resolver evaluated expressions within a privileged code section. A malicious web application could use this flaw to bypass security manager protections. (CVE-2014-7810 )");
  script_tag(name:"solution", value:"Run yum update tomcat8 to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-658.html");
  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2014-7810");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"The remote host is missing an update announced via the referenced Security Advisory.");
  script_copyright("Copyright (C) 2016 Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {
  if(!isnull(res = isrpmvuln(pkg:"tomcat8", rpm:"tomcat8~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-log4j", rpm:"tomcat8-log4j~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-lib", rpm:"tomcat8-lib~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-admin-webapps", rpm:"tomcat8-admin-webapps~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-javadoc", rpm:"tomcat8-javadoc~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-servlet-3.1-api", rpm:"tomcat8-servlet-3.1-api~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-el-3.0-api", rpm:"tomcat8-el-3.0-api~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-docs-webapp", rpm:"tomcat8-docs-webapp~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-jsp-2.3-api", rpm:"tomcat8-jsp-2.3-api~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-webapps", rpm:"tomcat8-webapps~8.0.30~1.57.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
