###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! Core 'Language Switcher' Module Cross Site Scripting Vulnerability (20180602)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813457");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2018-12711");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2018-06-27 15:36:27 +0530 (Wed, 27 Jun 2018)");

  script_name("Joomla! Core 'Language Switcher' Module Cross Site Scripting Vulnerability (20180602)");

  script_tag(name:"summary", value:"This host is running Joomla and is prone to cross site scripting
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to inadequate sanitization in the link of the current
language.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a reflected XSS
via injection of arbitrary parameters and/or values on the current page url.");

  script_tag(name:"affected", value:"Joomla core versions 1.6.0 through 3.8.8");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.8.9 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/740-20180602-core-xss-vulnerability-in-language-switcher-module");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:jPort, exit_no_version:TRUE )) exit(0);
jVer = infos['version'];
path = infos['location'];

if(version_in_range(version:jVer, test_version:"1.6.0", test_version2:"3.8.8")) {
  report = report_fixed_ver(installed_version:jVer, fixed_version:"3.8.9", install_path:path);
  security_message(port:jPort, data:report);
  exit(0);
}

exit(0);
