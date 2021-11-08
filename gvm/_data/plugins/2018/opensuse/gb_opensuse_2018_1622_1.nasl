# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851781");
  script_version("2020-06-03T08:38:58+0000");
  script_tag(name:"last_modification", value:"2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)");
  script_tag(name:"creation_date", value:"2018-06-10 05:48:37 +0200 (Sun, 10 Jun 2018)");
  script_cve_id("CVE-2018-10392");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for libvorbis (openSUSE-SU-2018:1622-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvorbis'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libvorbis fixes the following issues:

  The following security issue was fixed:

  - Fixed the validation of channels in mapping0_forward(), which previously
  allowed remote attackers to cause a denial of service via specially
  crafted files (CVE-2018-10392, bsc#1091070)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-591=1");

  script_tag(name:"affected", value:"libvorbis on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:1622-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00013.html");
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
  if(!isnull(res = isrpmvuln(pkg:"libvorbis-debugsource", rpm:"libvorbis-debugsource~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0", rpm:"libvorbis0~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0-debuginfo", rpm:"libvorbis0-debuginfo~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2", rpm:"libvorbisenc2~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2-debuginfo", rpm:"libvorbisenc2-debuginfo~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3", rpm:"libvorbisfile3~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3-debuginfo", rpm:"libvorbisfile3-debuginfo~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis-doc", rpm:"libvorbis-doc~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0-32bit", rpm:"libvorbis0-32bit~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0-debuginfo-32bit", rpm:"libvorbis0-debuginfo-32bit~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2-32bit", rpm:"libvorbisenc2-32bit~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2-debuginfo-32bit", rpm:"libvorbisenc2-debuginfo-32bit~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3-32bit", rpm:"libvorbisfile3-32bit~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3-debuginfo-32bit", rpm:"libvorbisfile3-debuginfo-32bit~1.3.3~17.1", rls:"openSUSELeap42.3"))) {
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
