###############################################################################
# OpenVAS Vulnerability Test
#
# Mageia Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (C) 2016 Eero Volotinen, http://www.solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131188");
  script_version("2020-08-04T08:27:56+0000");
  script_tag(name:"creation_date", value:"2016-01-18 07:49:20 +0200 (Mon, 18 Jan 2016)");
  script_tag(name:"last_modification", value:"2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)");
  script_name("Mageia Linux Local Check: mgasa-2016-0022");
  script_tag(name:"insight", value:"An information leak flaw was found in the way the OpenSSH client roaming feature was implemented. A malicious server could potentially use this flaw to leak portions of memory (possibly including private SSH keys) of a successfully authenticated OpenSSH client (CVE-2016-0777). A buffer overflow flaw was found in the way the OpenSSH client roaming feature was implemented. A malicious server could potentially use this flaw to execute arbitrary code on a successfully authenticated OpenSSH client if that client used certain non-default configuration options (CVE-2016-0778). The issue only affects OpenSSH clients making use of the ProxyCommand feature. This update disables the roaming feature completely.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0022.html");
  script_cve_id("CVE-2016-0777", "CVE-2016-0778");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Mageia Linux Local Security Checks mgasa-2016-0022");
  script_copyright("Copyright (C) 2016 Eero Volotinen");
  script_family("Mageia Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6p1~5.6.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
