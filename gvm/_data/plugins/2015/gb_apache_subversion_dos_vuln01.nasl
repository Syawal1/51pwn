###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Subversion Denial of Service Vulnerability -01 May15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805606");
  script_version("2020-11-25T09:16:10+0000");
  script_cve_id("CVE-2015-0248");
  script_bugtraq_id(74260);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)");
  script_tag(name:"creation_date", value:"2015-05-06 12:54:14 +0530 (Wed, 06 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Subversion Denial of Service Vulnerability -01 May15");

  script_tag(name:"summary", value:"This host is installed with Apache Subversion
  and is prone to denial of service  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to vulnerability in mod_dav_svn
  and svnserve servers in Subversion that is triggered when handling certain
  parameter combinations, which can force a server to attempt an operation with
  invalid arguments.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to cause a failed assertion, resulting in the current process being
  aborted via crafted parameter combinations related to dynamically evaluated
  revision numbers.");

  script_tag(name:"affected", value:"Subversion 1.6.0 through 1.7.19 and 1.8.0
  through 1.8.11.");

  script_tag(name:"solution", value:"Upgrade to version 1.7.20 or 1.8.13 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-04/msg00008.html");
  script_xref(name:"URL", value:"https://subversion.apache.org/security/CVE-2015-0248-advisory.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_subversion_remote_detect.nasl");
  script_mandatory_keys("Subversion/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!subver = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_in_range(version:subver, test_version:"1.6.0", test_version2:"1.7.19"))
{
  fix = "1.7.20";
  VULN = TRUE;
}

if(version_in_range(version:subver, test_version:"1.8.0", test_version2:"1.8.11"))
{
  fix = "1.8.13";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + subver + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report, port:http_port);
  exit(0);
}
