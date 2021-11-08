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
  script_oid("1.3.6.1.4.1.25623.1.0.120428");
  script_version("2020-03-13T13:19:50+0000");
  script_tag(name:"creation_date", value:"2015-09-08 13:26:11 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)");
  script_name("Amazon Linux: Security Advisory (ALAS-2014-445)");
  script_tag(name:"insight", value:"A flaw was found in the way rsyslog handled invalid log message priority values. In certain configurations, a local attacker, or a remote attacker able to connect to the rsyslog port, could use this flaw to crash the rsyslog daemon. (CVE-2014-3634 )");
  script_tag(name:"solution", value:"Run yum update rsyslog to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-445.html");
  script_cve_id("CVE-2014-3634");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"The remote host is missing an update announced via the referenced Security Advisory.");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
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
  if(!isnull(res = isrpmvuln(pkg:"rsyslog-mysql", rpm:"rsyslog-mysql~5.8.10~9.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-debuginfo", rpm:"rsyslog-debuginfo~5.8.10~9.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-pgsql", rpm:"rsyslog-pgsql~5.8.10~9.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-gnutls", rpm:"rsyslog-gnutls~5.8.10~9.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-gssapi", rpm:"rsyslog-gssapi~5.8.10~9.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~5.8.10~9.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-snmp", rpm:"rsyslog-snmp~5.8.10~9.26.amzn1", rls:"AMAZON"))) {
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
