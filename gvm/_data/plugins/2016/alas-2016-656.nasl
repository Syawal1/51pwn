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
  script_oid("1.3.6.1.4.1.25623.1.0.120646");
  script_version("2020-03-13T13:19:50+0000");
  script_tag(name:"creation_date", value:"2016-03-11 07:09:10 +0200 (Fri, 11 Mar 2016)");
  script_tag(name:"last_modification", value:"2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)");
  script_name("Amazon Linux: Security Advisory (ALAS-2016-656)");
  script_tag(name:"insight", value:"It was found that the expression language resolver evaluated expressions within a privileged code section. A malicious web application could use this flaw to bypass security manager protections. (CVE-2014-7810 )It was found that Tomcat would keep connections open after processing requests with a large enough request body. A remote attacker could potentially use this flaw to exhaust the pool of available connections and preventing further, legitimate connections to the Tomcat server to be made. (CVE-2014-0230 )");
  script_tag(name:"solution", value:"Run yum update tomcat6 to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-656.html");
  script_cve_id("CVE-2014-7810", "CVE-2014-0230");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
  if(!isnull(res = isrpmvuln(pkg:"tomcat6-el-2.1-api", rpm:"tomcat6-el-2.1-api~6.0.44~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.44~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.44~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-servlet-2.5-api", rpm:"tomcat6-servlet-2.5-api~6.0.44~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.44~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.44~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-jsp-2.1-api", rpm:"tomcat6-jsp-2.1-api~6.0.44~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.44~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.44~1.3.amzn1", rls:"AMAZON"))) {
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
