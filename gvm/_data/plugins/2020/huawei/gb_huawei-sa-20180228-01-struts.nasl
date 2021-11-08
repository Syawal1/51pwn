# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.107824");
  script_version("2020-06-05T12:34:50+0000");
  script_tag(name:"last_modification", value:"2020-06-05 12:34:50 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-7525");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Remote Code Execution Vulnerability in Jackson JSON library of Apache Struts2 (huawei-sa-20180228-01-struts)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Apache Struts2 released a remote code execution vulnerability in S2-055 on the official website.");

  script_tag(name:"insight", value:"Apache Struts2 released a remote code execution vulnerability in S2-055 on the official website. An attacker is possible to perform a Remote Code Execution(RCE) attack with a malicious JSON packet. (Vulnerability ID: HWPSIRT-2017-12002)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-7525.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker is possible to perform a RCE (Remote Code Execution) attack with a malicious JSON packet.");

  script_tag(name:"affected", value:"eSDK versions 3.1.0 3.1.0.SPC100");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180228-01-struts-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/o:huawei:_firmware" ); #no known vulnerable devices

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe =~ "^cpe:/o:huawei:_firmware" ) {
  if( version == "" || version == "" || version == "" || version == "" ||
      version == "" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
