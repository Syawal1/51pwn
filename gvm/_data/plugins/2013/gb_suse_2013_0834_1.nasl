# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850478");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:35 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1674",
                "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678",
                "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2013:0834-1)");

  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE 12.2");

  script_tag(name:"insight", value:"MozillaThunderbird was updated to security update
  Thunderbird 17.0.6 (bnc#819204):

  * MFSA 2013-41/CVE-2013-0801/CVE-2013-1669 Miscellaneous
  memory safety hazards

  * MFSA 2013-42/CVE-2013-1670 (bmo#853709) Privileged access
  for content level constructor

  * MFSA 2013-46/CVE-2013-1674 (bmo#860971) Use-after-free
  with video and onresize event

  * MFSA 2013-47/CVE-2013-1675 (bmo#866825) Uninitialized
  functions in DOMSVGZoomEvent

  * MFSA 2013-48/CVE-2013-1676/CVE-2013-1677/CVE-2013-1678/
  CVE-2013-1679/CVE-2013-1680/CVE-2013-1681 Memory
  corruption found using Address Sanitizer");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"openSUSE-SU", value:"2013:0834-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.2") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~17.0.6~49.43.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~17.0.6~49.43.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~17.0.6~49.43.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~17.0.6~49.43.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~17.0.6~49.43.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel-debuginfo", rpm:"MozillaThunderbird-devel-debuginfo~17.0.6~49.43.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~17.0.6~49.43.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~17.0.6~49.43.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.5.1+17.0.6~49.43.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail-debuginfo", rpm:"enigmail-debuginfo~1.5.1+17.0.6~49.43.1", rls:"openSUSE12.2"))) {
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
