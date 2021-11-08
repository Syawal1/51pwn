# Copyright (C) 2015 Eero Volotinen
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
  script_oid("1.3.6.1.4.1.25623.1.0.123334");
  script_version("2020-03-13T10:06:41+0000");
  script_tag(name:"creation_date", value:"2015-10-06 14:02:25 +0300 (Tue, 06 Oct 2015)");
  script_tag(name:"last_modification", value:"2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)");
  script_name("Oracle Linux Local Check: ELSA-2014-1038");
  script_tag(name:"insight", value:"ELSA-2014-1038 - tomcat6 security update. Please see the references for more insight.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Linux Local Security Checks ELSA-2014-1038");
  script_xref(name:"URL", value:"http://linux.oracle.com/errata/ELSA-2014-1038.html");
  script_cve_id("CVE-2014-0119", "CVE-2013-4590");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Oracle Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.24~78.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.24~78.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.24~78.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"tomcat6-el-2.1-api", rpm:"tomcat6-el-2.1-api~6.0.24~78.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.24~78.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"tomcat6-jsp-2.1-api", rpm:"tomcat6-jsp-2.1-api~6.0.24~78.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.24~78.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"tomcat6-servlet-2.5-api", rpm:"tomcat6-servlet-2.5-api~6.0.24~78.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.24~78.el6_5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

