# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851899");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-09-21 08:10:35 +0200 (Fri, 21 Sep 2018)");
  script_cve_id("CVE-2017-18233", "CVE-2017-18236", "CVE-2017-18238");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for exempi (openSUSE-SU-2018:2764-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exempi'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exempi fixes the following security issue:

  - CVE-2017-18236: The ASF_Support::ReadHeaderObject function allowed
  remote attackers to cause a denial of service (infinite loop) via a
  crafted .asf file (bsc#1085589)

  - CVE-2017-18233: Prevent integer overflow in the Chunk class that allowed
  remote attackers to cause a denial of service (infinite loop) via
  crafted XMP data in a .avi file (bsc#1085584)

  - CVE-2017-18238: The TradQT_Manager::ParseCachedBoxes function allowed
  remote attackers to cause a denial of service (infinite loop) via
  crafted XMP data in a .qt file (bsc#1085583)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1022=1");

  script_tag(name:"affected", value:"exempi on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2764-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00041.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"exempi-debugsource", rpm:"exempi-debugsource~2.2.2~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exempi-tools", rpm:"exempi-tools~2.2.2~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exempi-tools-debuginfo", rpm:"exempi-tools-debuginfo~2.2.2~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexempi-devel", rpm:"libexempi-devel~2.2.2~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexempi3", rpm:"libexempi3~2.2.2~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexempi3-debuginfo", rpm:"libexempi3-debuginfo~2.2.2~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexempi3-32bit", rpm:"libexempi3-32bit~2.2.2~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexempi3-debuginfo-32bit", rpm:"libexempi3-debuginfo-32bit~2.2.2~6.8.1", rls:"openSUSELeap42.3"))) {
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
