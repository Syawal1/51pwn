###############################################################################
# OpenVAS Vulnerability Test
#
# Dell SonicWALL Secure Mobile Access / Secure Remote Access Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107118");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-03-26T08:48:45+0000");
  script_tag(name:"last_modification", value:"2020-03-26 08:48:45 +0000 (Thu, 26 Mar 2020)");
  script_tag(name:"creation_date", value:"2017-01-09 13:26:09 +0700 (Mon, 09 Jan 2017)");

  script_name("SonicWall / Dell SonicWALL SMA / SRA Detection (SNMP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of SonicWall / Dell SonicWALL
  Secure Mobile Access (SMA) and Secure Remote Access (SRA).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = snmp_get_port( default:161 );
sysdesc = snmp_get_sysdesc( port:port );

if( sysdesc !~ '(Dell )?SonicWALL S[RM]A' )
  exit( 0 );

set_kb_item( name:"sonicwall/sra_sma/detected", value:TRUE );
set_kb_item( name:"sonicwall/sra_sma/snmp/port", value:port );
set_kb_item( name:"sonicwall/sra_sma/snmp/" + port + "/concluded", value:sysdesc );

product = "unknown";
version = "unknown";
series = "unknown";

prod = eregmatch( pattern:'(Dell )?SonicWALL ([A-Z]+)', string:sysdesc, icase:TRUE );
if( ! isnull( prod[2] ) )
  product = prod[2];

if( sysdesc =~ '(Dell )?SonicWALL S[R|M]A Virtual Appliance' ) {
  series = "Virtual Appliance";

  # Dell SonicWALL SRA Virtual Appliance ( 8.1.0.10-25sv)
  vers = eregmatch( string:sysdesc, pattern:"(Dell )?SonicWALL S[RM]A Virtual Appliance \( ([0-9.]+[^)]+)",
                    icase:TRUE );

  if( ! isnull( vers[1] ) )
    version = vers[1];
} else {
  # Dell SonicWALL SRA 4600 ( 8.5.0.0-13sv.03.jpn)
  # SonicWALL SRA 1200 (SonicOS SSL-VPN 4.0.0.3-20sv)
  # Dell SonicWALL SRA 4200 (SonicOS SSL-VPN 7.5.1.2-40sv)
  # SonicWall SRA 4600 (9.0.0.4-18sv)
  # Dell SonicWALL SRA 1600 ( 8.5.0.0-13sv)
  # SonicWall SMA 400 (9.0.0.3-17sv)
  vers = eregmatch( string:sysdesc,
                    pattern:"(Dell )?SonicWALL S[RM]A ([0-9]+) \(([A-Z ]+)?([^0-9]+)?([0-9.]+[^)]+)", icase:TRUE );

  if( ! isnull( vers[5] ) )
    version = vers[5];

  if( ! isnull( vers[2] ) )
    series = vers[2];
}

set_kb_item( name:"sonicwall/sra_sma/snmp/" + port + "/product", value:product );
set_kb_item( name:"sonicwall/sra_sma/snmp/" + port + "/series", value:series );
set_kb_item( name:"sonicwall/sra_sma/snmp/" + port + "/version", value:version );

exit( 0 );
