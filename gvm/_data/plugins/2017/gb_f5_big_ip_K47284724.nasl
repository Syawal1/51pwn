###############################################################################
# OpenVAS Vulnerability Test
#
# F5 BIG-IP - TMM vulnerability CVE-2016-9256
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107169");
  script_cve_id("CVE-2016-9256");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_version("2020-04-03T06:15:47+0000");

  script_name("F5 BIG-IP - TMM vulnerability CVE-2016-9256");

  script_xref(name:"URL", value:"https://support.f5.com/csp/article/K47284724");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Permissions enforced by iControl can lag behind the actual permissions assigned to a user if the role_map is not reloaded between the time the permissions are changed and the time of the user's next request. This is a race condition that occurs rarely in normal usage. The typical period in which this is possible is limited to at most a few seconds after the permission change. (CVE-2016-9256)");

  script_tag(name:"impact", value:"When an iControl user has administrative privileges that are later downgraded, the user will still be able to use their previous permissions using iControl until the role map reloads.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2020-04-03 06:15:47 +0000 (Fri, 03 Apr 2020)");

  script_tag(name:"creation_date", value:"2017-05-17 14:28:20 +0200 (Wed, 17 May 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_f5_big_ip_version.nasl");
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("list_array_func.inc");
include("f5.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

check_f5['LTM'] = make_array( 'affected',   '12.0.0-12.1.2;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.4.0-11.6.1;11.2.1;' );

check_f5['AAM'] = make_array( 'affected',   '12.0.0-12.1.2;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.4.0-11.6.1;' );

check_f5['AFM'] = make_array( 'affected',   '12.0.0-12.1.2;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.4.0-11.6.1;' );

check_f5['AVR'] = make_array( 'affected',   '12.0.0-12.1.2;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.4.0-11.6.1;11.2.1;' );

check_f5['APM'] = make_array( 'affected',   '12.0.0-12.1.2;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.4.0-11.6.1;11.2.1;' );

check_f5['ASM'] = make_array( 'affected',   '12.0.0-12.1.2;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.4.0-11.6.1;11.2.1;' );

check_f5['LC'] = make_array( 'affected',   '12.0.0-12.1.2;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.4.0-11.6.1;11.2.1;' );

check_f5['PEM'] = make_array( 'affected',   '12.0.0-12.1.2;',
                              'unaffected', '13.0.0;12.1.2_HF1;11.4.0-11.6.1;' );

if( report = f5_is_vulnerable( ca:check_f5, version:version ) ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
