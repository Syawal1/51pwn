###############################################################################
# OpenVAS Vulnerability Test
#
# This script allows to set SSH credentials for target hosts.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
# Chandrashekhar B <bchandra@secpod.com>
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2007,2008,2009,2010,2011,2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.90022");
  script_version("2020-11-12T09:50:32+0000");
  script_tag(name:"last_modification", value:"2020-11-12 09:50:32 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2007-11-01 23:55:52 +0100 (Thu, 01 Nov 2007)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Authorization Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2007-2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl", "ssh_authorization_init.nasl", "global_settings.nasl", "lsc_options.nasl");
  script_mandatory_keys("Secret/SSH/login");
  script_exclude_keys("global_settings/authenticated_scans_disabled");

  script_tag(name:"summary", value:"This script tries to login with provided credentials.

  If the login was successful, it marks this port as available for any authenticated tests.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if( get_kb_item( "global_settings/authenticated_scans_disabled" ) )
  exit( 0 );

include("ssh_func.inc");
include("host_details.inc");

# nb: Check if port for us is known
port = kb_ssh_transport();

# nb: Check if an account was defined either by the preferences ("old") or by the server ("new").
if( kb_ssh_login() && ( kb_ssh_password() || kb_ssh_privatekey() ) ) {

  if( ! port ) {
    reason = "No port for an SSH connect was found open. Hence authenticated checks are not enabled.";
    log_message( data:reason );
    set_kb_item( name:"login/SSH/failed", value:TRUE );
    set_kb_item( name:"login/SSH/failed/reason", value:reason );
    register_host_detail( name:"Auth-SSH-Failure", value:"Protocol SSH, User " + kb_ssh_login() + " : No port open" );
    exit( 0 ); # If port is not open
  }

  sock = ssh_login_or_reuse_connection();
  if( ! sock ) {
    # nb: This text is also used in ssh_login_failed.nasl within a comparison, changed it there as well if changing it here.
    reason = "It was not possible to login using the provided SSH credentials. Hence authenticated checks are not enabled.";
    log_message( port:port, data:reason );
    set_kb_item( name:"login/SSH/failed", value:TRUE );
    set_kb_item( name:"login/SSH/failed/port", value:port );
    set_kb_item( name:"login/SSH/failed/reason", value:reason );
    register_host_detail( name:"Auth-SSH-Failure", value:"Protocol SSH, Port " + port + ", User " + kb_ssh_login() + " : Login failure" );
    ssh_close_connection();
    exit( 0 );
  }

  # nb: This can't catch "keyboard-interactive" enabled systems because the password prompt is caught earlier directly in the SSH
  # functions of the scanner without returning a successful login.
  res = ssh_cmd( socket:sock, cmd:"echo 'login test'", timeout:60, pty:TRUE, return_errors:FALSE );
  if( res ) {
    foreach text( ssh_expired_pw_text ) {
      if( text >< res ) {
        reason = "The password of the provided SSH credentials has expired and the user is required to change it before a login is possible again. Hence authenticated checks are not enabled.";
        log_message( port:port, data:reason );
        set_kb_item( name:"login/SSH/failed", value:TRUE );
        set_kb_item( name:"login/SSH/failed/port", value:port );
        set_kb_item( name:"login/SSH/failed/reason", value:reason );
        register_host_detail( name:"Auth-SSH-Failure", value:"Protocol SSH, Port " + port + ", User " + kb_ssh_login() + " : Password expired" );
        ssh_close_connection();
        exit( 0 );
      }
    }
  }

  set_kb_item( name:"login/SSH/success", value:TRUE );
  set_kb_item( name:"login/SSH/success/port", value:port );
  register_host_detail( name:"Auth-SSH-Success", value:"Protocol SSH, Port " + port + ", User " + kb_ssh_login() );

  log_message( port:port, data:"It was possible to login using the provided SSH credentials. Hence authenticated checks are enabled." );
  ssh_close_connection();
} else {
  # Actually it is not necessary to send log information in case no
  # credentials at all were provided. The user simply does not want
  # to run an authenticated scan.
  #log_message(data:'No sufficient SSH credentials were supplied.\nHence authenticated checks are not enabled.', port:port);
}

exit( 0 );
