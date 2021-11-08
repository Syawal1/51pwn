###############################################################################
# OpenVAS Vulnerability Test
#
# SSH Brute Force Logins With Default Credentials Reporting
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103239");
  script_version("2020-11-12T08:36:45+0000");
  script_tag(name:"last_modification", value:"2020-11-12 08:36:45 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2016-11-02 11:47:00 +0100 (Wed, 02 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SSH Brute Force Logins With Default Credentials Reporting");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_END);
  script_family("Brute force attacks");
  script_dependencies("default_ssh_credentials.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("default_ssh_credentials/started");

  script_add_preference(name:"Report timeout", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"It was possible to login into the remote SSH server using default credentials.

  As the VT 'SSH Brute Force Logins With Default Credentials' (OID: 1.3.6.1.4.1.25623.1.0.108013) might run into a
  timeout the actual reporting of this vulnerability takes place in this VT instead. The script preference 'Report timeout'
  allows you to configure if such a timeout is reported.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"vuldetect", value:"Reports default credentials detected by the VT 'SSH Brute Force Logins With Default Credentials'
  (OID: 1.3.6.1.4.1.25623.1.0.108013).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

credentials = get_kb_list( "default_ssh_credentials/" + port + "/credentials" );

if( ! isnull( credentials ) ) {

  report = 'It was possible to login with the following credentials <User>:<Password>\n\n';

  # Sort to not report changes on delta reports if just the order is different
  credentials = sort( credentials );

  foreach credential( credentials ) {
    report += credential + '\n';
    vuln = TRUE;
  }
}

reportTimeout = script_get_preference( "Report timeout", id:1 );
if( reportTimeout == "yes" ) {
  if( ! get_kb_item( "default_ssh_credentials/" + port + "/no_timeout" ) ) {
    timeoutReport = "A timeout happened during the test for default logins. " +
                    "Consider raising the script_timeout value of the VT " +
                    "'SSH Brute Force Logins With Default Credentials' " +
                    "(OID: 1.3.6.1.4.1.25623.1.0.108013).";
    log_message( port:port, data:timeoutReport );
  }
}

if( vuln ) {
  c = get_kb_item( "default_ssh_credentials/" + port + "/too_many_logins" );
  if( c ) {
    report += '\nRemote host accept more than ' + c + ' logins. This could indicate some error or some "broken" device.\nScanner stops testing for default logins at this point.';
  }
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
