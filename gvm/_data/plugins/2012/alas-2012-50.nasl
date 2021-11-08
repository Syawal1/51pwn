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
  script_oid("1.3.6.1.4.1.25623.1.0.120417");
  script_version("2020-03-13T13:19:50+0000");
  script_tag(name:"creation_date", value:"2015-09-08 13:25:54 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)");
  script_name("Amazon Linux: Security Advisory (ALAS-2012-50)");
  script_tag(name:"insight", value:"Multiple cross-site scripting (XSS) vulnerabilities in config.c in config.cgi in (1) Nagios 3.2.3 and (2) Icinga before 1.4.1 allow remote attackers to inject arbitrary web script or HTML via the expand parameter, as demonstrated by an (a) command action or a (b) hosts action.");
  script_tag(name:"solution", value:"Run yum update nagios to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-50.html");
  script_cve_id("CVE-2011-2179");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
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
  if(!isnull(res = isrpmvuln(pkg:"nagios-debuginfo", rpm:"nagios-debuginfo~3.3.1~3.4.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios", rpm:"nagios~3.3.1~3.4.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-devel", rpm:"nagios-devel~3.3.1~3.4.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-common", rpm:"nagios-common~3.3.1~3.4.amzn1", rls:"AMAZON"))) {
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
