###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Websphere Application Server Privilege Escalation Vulnerability Mar16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807622");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2015-1885");
  script_bugtraq_id(74219);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2016-03-21 14:49:58 +0530 (Mon, 21 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server Privilege Escalation Vulnerability Mar16");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  application server and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws is due to when
  OAuth grant type of password is used.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges on the system.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  7.0 before 7.0.0.39, 8.0 before 8.0.0.11, 8.5 Liberty Profile before 8.5.5.5,
  and 8.5 Full Profile before 8.5.5.6");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21697368");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.38"))
{
  fix = "7.0.0.39";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.0", test_version2:"8.0.0.10"))
{
  fix = "8.0.0.11";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.5.4"))
{
  fix = "8.5.5.5";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
