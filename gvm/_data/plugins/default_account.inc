###############################################################################
# OpenVAS Include File
#
# Support for various ways of determining if an account is valid
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2004 Renaud Deraison
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# Private functions
function recv_until( socket, pattern ) {

  local_var socket, pattern;
  local_var i, r, buf;

  i = 0;

  while( TRUE ) {
    i++;
    if( i > 65535 )
      return NULL;

    r = recv( socket:socket, length:1 );
    if( strlen( r ) == 0 )
      return NULL;

    buf += r;
    if( egrep( pattern:pattern, string:buf ) )
      return buf;
  }
}

function _check_telnet( port, login, password ) {

  local_var port, login, password;
  local_var soc, res;

  soc = open_sock_tcp( port );
  if( ! soc )
    return( 0 );

  res = telnet_init( soc );
  res += recv_until( socket:soc, pattern:"ogin:" );
  if( ! res )
    exit( 0 );

  send( socket:soc, data:login + '\r\n' );
  if( isnull( password ) ) {
    send( socket:soc, data:'id\r\n' );
    res = recv_until( socket:soc, pattern:"uid=" );
    close( soc );
    if( res )
      return 1;
    else
      return 0;
  }

  res = recv_until( socket:soc, pattern:"word:" );
  if( isnull( res ) ) {
    close( soc );
    return 0;
  }

  send( socket:soc, data:password + '\r\n' );
  send( socket:soc, data:'id\r\n' );

  res = recv_until( socket:soc, pattern:"uid=" );
  close( soc );
  if( res )
    return 1;
  else
    return 0;
}

#-------------------------------------------------------------------#

function check_account( login, password ) {

  local_var login, password;
  local_var port, ret, soc, res;

  if( ! login ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#login#-#check_account" );

  # Prefer login through SSH rather than telnet
  ports = ssh_get_ports( default_port_list:make_list( 22 ) );
  foreach port( ports ) {
    # Check if any random user/pass pair is accepted by the SSH service first.
    if( ! ssh_broken_random_login( port:port ) ) {
      soc = open_sock_tcp( port );
      if( soc ) {
        ret = ssh_login( socket:soc, login:login, password:password, priv:NULL, passphrase:NULL );
        close( soc );
        if( ret == 0 )
          return port;
      }
    }
  }

  port = telnet_get_port( default:23 );

  if( get_kb_item( "telnet/" + port + "/no_login_banner" ) )
    return;

  if( isnull( password ) )
    password = "";

  res = _check_telnet( port:port, login:login, password:password );
  if( res )
    return port;
  else
    return;
}
