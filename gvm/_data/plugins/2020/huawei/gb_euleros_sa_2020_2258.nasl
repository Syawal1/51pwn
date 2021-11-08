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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.2258");
  script_version("2020-10-30T10:45:05+0000");
  script_cve_id("CVE-2020-14093", "CVE-2020-14154", "CVE-2020-14954");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-10-30 10:45:05 +0000 (Fri, 30 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-30 10:45:05 +0000 (Fri, 30 Oct 2020)");
  script_name("Huawei EulerOS: Security Advisory for mutt (EulerOS-SA-2020-2258)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"EulerOS-SA", value:"2020-2258");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2258");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'mutt' package(s) announced via the EulerOS-SA-2020-2258 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mutt before 1.14.3 allows an IMAP fcc/postpone man-in-the-middle attack via a PREAUTH response.(CVE-2020-14093)

Mutt before 1.14.4 and NeoMutt before 2020-06-19 have a STARTTLS buffering issue that affects IMAP, SMTP, and POP3. When a server sends a 'begin TLS' response, the client reads additional data (e.g., from a man-in-the-middle attacker) and evaluates it in a TLS context, aka 'response injection.'(CVE-2020-14954)

Mutt before 1.14.3 proceeds with a connection even if, in response to a GnuTLS certificate prompt, the user rejects an expired intermediate certificate.(CVE-2020-14154)");

  script_tag(name:"affected", value:"'mutt' package(s) on Huawei EulerOS V2.0SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.5.21~28.h4.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);