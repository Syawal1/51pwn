###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle iPlanet Web Server Multiple Unspecified Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801607");
  script_version("2020-03-10T08:16:09+0000");
  script_tag(name:"last_modification", value:"2020-03-10 08:16:09 +0000 (Tue, 10 Mar 2020)");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_bugtraq_id(43984);
  script_cve_id("CVE-2010-3544", "CVE-2010-3545");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Oracle iPlanet Web Server Multiple Unspecified vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl");
  script_mandatory_keys("java_system_web_server/installed");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to affect confidentiality,
  integrity and availability via unknown vectors related to Administration.");

  script_tag(name:"affected", value:"Oracle iPlanet Web Server(Sun Java System Web Server) 7.0.");

  script_tag(name:"insight", value:"The flaws are due to unspecified errors, which allow remote attackers
  to affect confidentiality, integrity and availability via unknown vectors related to Administration.");

  script_tag(name:"summary", value:"The host is running Oracle iPlanet Web Server and is prone to
  multiple unspecified vulnerabilities.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:sun:iplanet_web_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "7.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Apply the patch.", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
