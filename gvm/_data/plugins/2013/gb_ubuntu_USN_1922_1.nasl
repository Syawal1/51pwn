###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for evolution-data-server USN-1922-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841520");
  script_version("2020-02-13T09:17:49+0000");
  script_tag(name:"last_modification", value:"2020-02-13 09:17:49 +0000 (Thu, 13 Feb 2020)");
  script_tag(name:"creation_date", value:"2013-08-08 11:47:35 +0530 (Thu, 08 Aug 2013)");
  script_cve_id("CVE-2013-4166");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Ubuntu Update for evolution-data-server USN-1922-1");

  script_tag(name:"affected", value:"evolution-data-server on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Yves-Alexis Perez discovered that Evolution Data Server did not properly
select GPG recipients. Under certain circumstances, this could result in
Evolution encrypting email to an unintended recipient.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"USN", value:"1922-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1922-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution-data-server'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|12\.10|13\.04)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libcamel-1.2-29", ver:"3.2.3-0ubuntu7.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libcamel-1.2-40", ver:"3.6.2-0ubuntu0.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"libcamel-1.2-40", ver:"3.6.4-0ubuntu1.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
