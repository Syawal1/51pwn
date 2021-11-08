###############################################################################
# OpenVAS Vulnerability Test
# Description: Determine which version of BIND name daemon is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2005 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10028");
  script_version("2019-12-10T15:03:15+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-10 15:03:15 +0000 (Tue, 10 Dec 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("ISC BIND 'named' Detection (Remote)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 SecuriTeam");
  script_family("Product detection");
  script_dependencies("dns_server.nasl", "dns_server_tcp.nasl");
  script_mandatory_keys("DNS/identified");

  script_xref(name:"URL", value:"https://www.isc.org/bind/");

  # start report off with generic description ... lots of proprietary DNS servers (Cisco, QIP, a bunch more
  # are all BIND-based...
  script_tag(name:"summary", value:"BIND 'named' is an open-source DNS server from isc.org. Many proprietary
  DNS servers are based on BIND source code.");

  script_tag(name:"insight", value:"The BIND based name servers (or DNS servers) allow remote users
  to query for version and type information. The query of the CHAOS TXT record 'version.bind', will
  typically prompt the server to send the information back to the querying source.");

  script_tag(name:"solution", value:"Using the 'version' directive in the 'options' section will block
  the 'version.bind' query, but it will not log such attempts.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

base_cpe = "cpe:/a:isc:bind";

function getVersion( data, port, proto ) {

  local_var data, port, proto;
  local_var ver, version, update, cpe;

  # nb: Some testing pattern for the complex regex below:
  #
  # data = "9.9.5-9+deb8u14-Debian";
  # data = "9.8.2rc1-RedHat-9.8.2-0.68.rc1.el6";
  # data = "9.11.4-P2-RedHat-9.11.4-9.P2.el7";
  # data = "9.7.0-P1";
  # data = "9.8.7-W1";
  # data = "9.4-ESV";
  # data = "9.4-ESVb1";
  # data = "9.6-ESV-R11-W1";
  # data = "9.6-ESV-R5-P1";
  # data = "9.4-ESV-R5b1";
  # data = "9.6-ESV-R8rc1";
  # data = "9.6.0a1";
  # data = "9.6.0b1";
  # data = "9.2.5beta2";
  # data = "9.3.5-P2-W1";
  # data = "9.10.3-P4-Ubuntu";
  # data = "9.11.3-1ubuntu1.11-Ubuntu";
  # data = "ISC BIND 8.4.4";
  # data = "ISC BIND 8.3.0-RC1 -- 8.4.4";
  # data = "9.11.3-S1"; -> "Supported Preview Edition"

  # nb: Other products like dnsmasq and similar have a text pattern like dnsmasq-1.2.3 prepended
  # so we should be able to differentiate here if the version response doesn't start with something
  # like e.g. "9.4". That's why the "^" anchor is used.
  ver = eregmatch( pattern:"^((ISC )?BIND )?([0-9.]{3,})(-ESV-?|-)?((rc|RC|P|R|W|S|a|b|beta)[0-9]+)?(-?(rc|RC|P|R|W|S|a|b|beta)[0-9]+)?", string:data, icase:FALSE );
  if( ! ver[3] )
    return;

  version = ver[3];
  cpe = base_cpe + ":" + version;

  if( ver[5] ) {
    update = ver[5];
    if( ver[7] )
      update += ver[7];

    version += " " + update;

    # nb: NVD CPE database is using "r11_w1" for "R11-W1" or "p2_w1" for "P2-W1".
    update = ereg_replace( string:update, pattern: "-", replace: "_" );
    cpe += ":" + tolower( update );
  }

  set_kb_item( name:"isc/bind/detected", value:TRUE );

  register_product( cpe:cpe, location:port + "/" + proto, port:port, proto:proto, service:"domain" );
  log_message( data:build_detection_report( app:"ISC BIND",
                                            version:version,
                                            install:port + "/" + proto,
                                            cpe:cpe,
                                            concluded:data ),
               port:port,
               proto:proto );
}

udp_Ports = get_kb_list( "DNS/udp/version_request" );
foreach port( udp_Ports ) {

  data = get_kb_item( "DNS/udp/version_request/" + port );
  if( ! data )
    continue;

  # Don't detect dnsmasq or PowerDNS as BIND.
  if( "dnsmasq" >< tolower( data ) || "powerdns" >< tolower( data ) )
    continue;

  getVersion( data:data, port:port, proto:"udp" );
}


tcp_Ports = get_kb_list( "DNS/tcp/version_request" );
foreach port( tcp_Ports ) {

  data = get_kb_item( "DNS/tcp/version_request/" + port );
  if( ! data )
    continue;

  # Don't detect dnsmasq or PowerDNS as BIND.
  if( "dnsmasq" >< tolower( data ) || "powerdns" >< tolower( data ) )
    continue;

  getVersion( data:data, port:port, proto:"tcp" );
}

exit( 0 );
