###############################################################################
# OpenVAS Vulnerability Test
#
# Citrix XenServer Multiple Security Updates (CTX214954)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105833");
  script_cve_id("CVE-2016-6258", "CVE-2016-6259");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2020-04-02T13:53:24+0000");

  script_name("Citrix XenServer Multiple Security Updates (CTX214954)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX214954");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in
  Citrix XenServer that may allow a malicious administrator of a PV guest VM to compromise or crash the host.");

  script_tag(name:"affected", value:"These vulnerabilities affect all currently supported versions of Citrix
  XenServer up to and including Citrix XenServer 7.0.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2020-04-02 13:53:24 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2016-07-28 18:00:20 +0200 (Thu, 28 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  exit(0);
}

include("citrix_version_func.inc");
include("host_details.inc");
include("list_array_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( ! hotfixes = get_kb_item("xenserver/patches") )
  exit( 0 );

patches = make_array();

patches['7.0.0'] = make_list( 'XS70E008' );
patches['6.5.0'] = make_list( 'XS65ESP1034' );
patches['6.2.0'] = make_list( 'XS62ESP1045' );
patches['6.1.0'] = make_list( 'XS61E071' );
patches['6.0.2'] = make_list( 'XS602E052', 'XS602ECC033' );
patches['6.0.0'] = make_list( 'XS60E062' );

citrix_xenserver_check_report_is_vulnerable( version:version, hotfixes:hotfixes, patches:patches );

exit( 99 );
