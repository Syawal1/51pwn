###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2016:1217 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882504");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-06-17 05:19:36 +0200 (Fri, 17 Jun 2016)");
  script_cve_id("CVE-2016-2818", "CVE-2016-2819", "CVE-2016-2821", "CVE-2016-2822",
                "CVE-2016-2828", "CVE-2016-2831");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2016:1217 centos5");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 45.2.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2016-2818, CVE-2016-2819, CVE-2016-2821, CVE-2016-2822,
CVE-2016-2828, CVE-2016-2831)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges sushi Anton Larsson, firehack, Jordi Chancel,
Christian Holler, Sylvestre Ledru, Tyson Smith, jomo, Jesse Ruderman,
Julian Seward, Timothy Nikkel, Karl Tomlinson, Olli Pettay, and Gary Kwong
as the original reporters.");
  script_tag(name:"affected", value:"firefox on CentOS 5");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:1217");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-June/021907.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~45.2.0~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
