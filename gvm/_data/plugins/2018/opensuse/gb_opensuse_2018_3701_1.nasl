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
  script_oid("1.3.6.1.4.1.25623.1.0.852112");
  script_version("2020-01-31T08:23:39+0000");
  script_cve_id("CVE-2018-16391", "CVE-2018-16392", "CVE-2018-16393", "CVE-2018-16418",
                "CVE-2018-16419", "CVE-2018-16420", "CVE-2018-16422", "CVE-2018-16423",
                "CVE-2018-16426", "CVE-2018-16427");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-11-10 05:57:39 +0100 (Sat, 10 Nov 2018)");
  script_name("openSUSE: Security Advisory for opensc (openSUSE-SU-2018:3701-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2018:3701-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00010.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc'
  package(s) announced via the openSUSE-SU-2018:3701-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opensc fixes the following issues:

  - CVE-2018-16391: Fixed a denial of service when handling responses from a
  Muscle Card (bsc#1106998)

  - CVE-2018-16392: Fixed a denial of service when handling responses from a
  TCOS Card (bsc#1106999)

  - CVE-2018-16393: Fixed buffer overflows when handling responses from
  Gemsafe V1 Smartcards (bsc#1108318)

  - CVE-2018-16418: Fixed buffer overflow when handling string concatenation
  in util_acl_to_str (bsc#1107039)

  - CVE-2018-16419: Fixed several buffer overflows when handling responses
  from a Cryptoflex card (bsc#1107107)

  - CVE-2018-16420: Fixed buffer overflows when handling responses from an
  ePass 2003 Card (bsc#1107097)

  - CVE-2018-16422: Fixed single byte buffer overflow when handling
  responses from an esteid Card (bsc#1107038)

  - CVE-2018-16423: Fixed double free when handling responses from a
  smartcard (bsc#1107037)

  - CVE-2018-16426: Fixed endless recursion when handling responses from an
  IAS-ECC card (bsc#1107034)

  - CVE-2018-16427: Fixed out of bounds reads when handling responses in
  OpenSC (bsc#1107033)


  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1384=1");

  script_tag(name:"affected", value:"opensc on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.13.0~9.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debuginfo", rpm:"opensc-debuginfo~0.13.0~9.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debugsource", rpm:"opensc-debugsource~0.13.0~9.3.1", rls:"openSUSELeap42.3"))) {
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