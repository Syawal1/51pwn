###############################################################################
# OpenVAS Vulnerability Test
#
# OpenVAS / Greenbone Vulnerability Manager Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103825");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2013-11-08 12:24:10 +0100 (Fri, 08 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OpenVAS / Greenbone Vulnerability Manager Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service3.nasl");
  script_require_ports("Services/omp_gmp", 9390);

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  determine if it is a OpenVAS Manager (openvasmd) or Greebone Vulnerability Manager (gmvd).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");
include("version_func.inc");

port = service_get_port( default:9390, proto:"omp_gmp" );
soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

req = "<get_version/>";
send( socket:soc, data:req + '\r\n' );
res = recv( socket:soc, length:256 );
close( soc );

# Examples:
# GOS 3.1 / OpenVAS-8 and probably prior:  <get_version_response status="200" status_text="OK"><version>6.0</version></get_version_response>
# GOS 4.x+ / OpenVAS-9 / GVM-10 and later: <get_version_response status="200" status_text="OK"><version>20.08</version></get_version_response>
if( ! res || res !~ "<get_version_response.+</get_version_response>" )
  exit( 0 );

set_kb_item( name:"openvasmd_gvmd/detected", value:TRUE );
set_kb_item( name:"openvas_gvm/framework_component/detected", value:TRUE );

manager_version = "unknown";
proto_version = "unknown";
install = port + "/tcp";
proto = "omp_gmp";

# nb: Defaults if we're not able to catch the version later (which basically shouldn't happen).
app_name = "OpenVAS / Greenbone Vulnerability Manager";
base_cpe = "cpe:/a:greenbone:greenbone_vulnerability_manager";
concluded = " - OMP/GMP protocol version request:  " + req + '\n';
concluded += " - OMP/GMP protocol version response: " + res;

ver = eregmatch( pattern:"<get_version_response.+<version>([0-9.]+)</version>", string:res );
if( ver[1] ) {
  proto_version = ver[1];
  # We can fingerprint the major OpenVAS / Greenbone Vulnerability Manager version from the supported OMP/GMP
  # protocol version. The OMP/GMP protocol version is currently matching the OpenVAS / Greenbone Vulnerability Manager
  # protocol but that could change so this needs to be verified from time to time. See https://docs.greenbone.net/#api_documentation
  manager_version = proto_version;
}

if( version_is_less( version:proto_version, test_version:"8.0" ) ) {
  app_name = "OpenVAS Manager";
  base_cpe = "cpe:/a:openvas:openvas_manager";
  concluded = " - OMP protocol version request:  " + req + '\n';
  concluded += " - OMP protocol version response: " + ver[0];
} else {
  app_name = "Greenbone Vulnerability Manager";
  base_cpe = "cpe:/a:greenbone:greenbone_vulnerability_manager";
  concluded = " - GMP protocol version request:  " + req + '\n';
  concluded += " - GMP protocol version response: " + ver[0];
}

cpe = build_cpe( value:manager_version, exp:"^([0-9.]+)", base:base_cpe + ":" );
if( ! cpe )
  cpe = base_cpe;

service_register( port:port, proto:proto );
register_product( cpe:cpe, location:install, port:port, service:proto );
register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port, desc:"OpenVAS / Greenbone Vulnerability Manager Detection", runs_key:"unixoide" );

log_message( data:build_detection_report( app:app_name,
                                          version:manager_version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:concluded ),
                                          port:port );

exit( 0 );
