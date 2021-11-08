# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852976");
  script_version("2020-03-13T09:37:47+0000");
  script_cve_id("CVE-2019-5844", "CVE-2019-5845", "CVE-2019-5846", "CVE-2020-6377");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-03-13 09:37:47 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-01-12 04:00:16 +0000 (Sun, 12 Jan 2020)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2020:0006-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0006-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00004.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:0006-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium version 79.0.3945.117 fixes the following issues:

  - CVE-2020-6377: Fixed a use-after-free in audio

  - Various fixes from internal audits, fuzzing and other initiatives

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-6=1");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"libre2-0", rpm:"libre2-0~20200101~lp151.10.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-0-debuginfo", rpm:"libre2-0-debuginfo~20200101~lp151.10.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-debugsource", rpm:"re2-debugsource~20200101~lp151.10.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-devel", rpm:"re2-devel~20200101~lp151.10.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~79.0.3945.117~lp151.2.57.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~79.0.3945.117~lp151.2.57.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~79.0.3945.117~lp151.2.57.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~79.0.3945.117~lp151.2.57.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~79.0.3945.117~lp151.2.57.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-0-32bit", rpm:"libre2-0-32bit~20200101~lp151.10.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-0-32bit-debuginfo", rpm:"libre2-0-32bit-debuginfo~20200101~lp151.10.6.1", rls:"openSUSELeap15.1"))) {
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
