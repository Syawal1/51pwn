###############################################################################
# OpenVAS Vulnerability Test
#
# Riverbed SteelCentral SSH Default Credentials
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105791");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-06-30 17:36:06 +0200 (Thu, 30 Jun 2016)");
  script_name("Riverbed SteelCentral SSH Default Credentials");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_openssh_remote_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/ssh/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Riverbed SteelCentral is prone to a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

users = make_list("mazu", "dhcp", "root");
pass = 'bb!nmp4y';

foreach user ( users )
{
  if( ! soc = open_sock_tcp( port ) ) exit( 0 );
  login = ssh_login( socket:soc, login:user, password:pass, priv:NULL, passphrase:NULL );

  if(login == 0)
  {
    cmd = ssh_cmd( socket:soc, cmd:'id', nosh:TRUE );
    close( soc );

    if( cmd =~ 'uid=[0-9]+.*gid=[0-9]+' )
    {
      affected_users += user + '\n';
      cmd_result += cmd + '\n';
    }
  }
}

if( affected_users )
{
  report = 'It was possible to login and to execute the `id` command with the following users and the password `' + pass + '`\n\n' + affected_users + '\nid command result:\n' + cmd_result;
  security_message( port:port, data:report );
  exit( 0 );
}

if( soc ) close( soc );

exit( 0 );
