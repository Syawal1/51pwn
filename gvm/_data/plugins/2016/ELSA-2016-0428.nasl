###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Linux Local Check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.fi>
#
# Copyright:
# Copyright (C) 2016 Eero Volotinen, http://solinor.fi
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
  script_oid("1.3.6.1.4.1.25623.1.0.122893");
  script_version("2020-08-04T08:27:56+0000");
  script_tag(name:"creation_date", value:"2016-03-11 07:06:38 +0200 (Fri, 11 Mar 2016)");
  script_tag(name:"last_modification", value:"2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)");
  script_name("Oracle Linux Local Check: ELSA-2016-0428");
  script_tag(name:"insight", value:"ELSA-2016-0428 - libssh2 security update. Please see the references for more insight.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Linux Local Security Checks ELSA-2016-0428");
  script_xref(name:"URL", value:"http://linux.oracle.com/errata/ELSA-2016-0428.html");
  script_cve_id("CVE-2016-0787");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux(7|6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Eero Volotinen");
  script_family("Oracle Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"libssh2", rpm:"libssh2~1.4.3~10.el7_2.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.4.3~10.el7_2.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"libssh2-docs", rpm:"libssh2-docs~1.4.3~10.el7_2.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"libssh2", rpm:"libssh2~1.4.2~2.el6_7.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.4.2~2.el6_7.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"libssh2-docs", rpm:"libssh2-docs~1.4.2~2.el6_7.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

