# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851212");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-03-01 11:08:58 +0530 (Tue, 01 Mar 2016)");
  script_cve_id("CVE-2007-4772", "CVE-2016-0766", "CVE-2016-0773");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for postgresql93 (openSUSE-SU-2016:0531-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql93'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql93 fixes the following issues:

  - Security and bugfix release 9.3.11:

  * Fix infinite loops and buffer-overrun problems in regular expressions
  (CVE-2016-0773, boo#966436).

  * Fix regular-expression compiler to handle loops of constraint arcs
  (CVE-2007-4772).

  * Prevent certain PL/Java parameters from being set by non-superusers
  (CVE-2016-0766, boo#966435).

  * Fix many issues in pg_dump with specific object types

  * Prevent over-eager pushdown of HAVING clauses for GROUPING SETS

  * Fix deparsing error with ON CONFLICT ... WHERE clauses

  * Fix tableoid errors for postgres_fdw

  * Prevent floating-point exceptions in pgbench

  * Make \det search Foreign Table names consistently

  * Fix quoting of domain constraint names in pg_dump

  * Prevent putting expanded objects into Const nodes

  * Allow compile of PL/Java on Windows

  * Fix 'unresolved symbol' errors in PL/Python execution

  * Allow Python2 and Python3 to be used in the same database

  * Add support for Python 3.5 in PL/Python

  * Fix issue with subdirectory creation during initdb

  * Make pg_ctl report status correctly on Windows

  * Suppress confusing error when using pg_receivexlog with older servers

  * Multiple documentation corrections and additions

  * Fix erroneous hash calculations in gin_extract_jsonb_path()

  - See the feferences for the full release notes.");

  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.3/static/release-9-3-11.html");

  script_tag(name:"affected", value:"postgresql93 on openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:0531-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib-debuginfo", rpm:"postgresql93-contrib-debuginfo~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debugsource", rpm:"postgresql93-debugsource~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-devel", rpm:"postgresql93-devel~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-devel-debuginfo", rpm:"postgresql93-devel-debuginfo~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-libs-debugsource", rpm:"postgresql93-libs-debugsource~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-plperl", rpm:"postgresql93-plperl~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-plperl-debuginfo", rpm:"postgresql93-plperl-debuginfo~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-plpython", rpm:"postgresql93-plpython~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-plpython-debuginfo", rpm:"postgresql93-plpython-debuginfo~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-pltcl", rpm:"postgresql93-pltcl~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-pltcl-debuginfo", rpm:"postgresql93-pltcl-debuginfo~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server-debuginfo", rpm:"postgresql93-server-debuginfo~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-test", rpm:"postgresql93-test~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit", rpm:"libecpg6-32bit~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo-32bit", rpm:"libecpg6-debuginfo-32bit~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo-32bit", rpm:"libpq5-debuginfo-32bit~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.11~2.10.1", rls:"openSUSE13.2"))) {
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
