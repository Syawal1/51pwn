###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Multiple Vulnerabilities -05 June 13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803823");
  script_version("2020-06-04T13:01:45+0000");
  script_cve_id("CVE-2013-2467");
  script_bugtraq_id(60649);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-04 13:01:45 +0000 (Thu, 04 Jun 2020)");
  script_tag(name:"creation_date", value:"2013-06-24 18:12:09 +0530 (Mon, 24 Jun 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -05 June 13 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpujun2013-1899847.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpujun2013verbose-1899853.html");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors. Attackers can even execute
  arbitrary code on the target system.");

  script_tag(name:"affected", value:"Oracle Java SE Version 5.0 Update 45 and earlier.");

  script_tag(name:"insight", value:"Flaws are due to unspecified errors related to Java Installer.");

  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to
  multiple vulnerabilities.");

  script_tag(name:"solution", value:"Update to Java SE Version 6 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

cpe_list = make_list( "cpe:/a:sun:jre:", "cpe:/a:oracle:jre:");

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range(version: vers, test_version: "1.5.0.0", test_version2: "1.5.0.45" ) ) {
  report = report_fixed_ver( installed_version: vers, vulnerable_range: "1.5.0.0 - 1.5.0.45", fixed_version: "Java SE Version 6", install_path: path );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
