###############################################################################
# OpenVAS Vulnerability Test
#
# Comodo Internet Security Denial of Service Vulnerability-01
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803687");
  script_version("2020-04-21T11:03:03+0000");
  script_cve_id("CVE-2010-5186");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2013-07-05 15:45:49 +0530 (Fri, 05 Jul 2013)");
  script_name("Comodo Internet Security Denial of Service Vulnerability-01");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/429015.php");
  script_xref(name:"URL", value:"http://personalfirewall.comodo.com/release_notes.html");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_comodo_internet_security_detect_win.nasl");
  script_mandatory_keys("Comodo/InternetSecurity/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to cause denial of service condition
  via crafted file.");
  script_tag(name:"affected", value:"Comodo Internet Security versions before 4.1.150349.920");
  script_tag(name:"insight", value:"Flaw related to the antivirus component, triggered when a user opens an
  unspecified malformed file.");
  script_tag(name:"solution", value:"Upgrade to Comodo Internet Security version 4.1.150349.920 or later.");
  script_tag(name:"summary", value:"The host is installed with Comodo Internet Security and is prone
  to denial of service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

Ver = get_kb_item("Comodo/InternetSecurity/Win/Ver");

if(Ver)
{
  if(version_is_less(version:Ver, test_version:"4.1.150349.920")){
    report = report_fixed_ver(installed_version:Ver, fixed_version:"4.1.150349.920");
    security_message(port:0, data:report);
    exit(0);
  }
}
