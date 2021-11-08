###############################################################################
# OpenVAS Include File
#
# Miscellaneous support methods
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Veerendra G.G <veerendragg@secpod.com>
# Added new rpc_construct_packet() function to construct rpc packet
#
# Copyright:
# Copyright (C) 2002 Michel Arboi <arboi@alussinan.org>
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

function rand_str( length, charset ) {

  local_var l, i, s, n, length, charset;

  if( ! charset )
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
  if( isnull( length ) )
    length = 8;
  l = strlen( charset );
  s = "";
  for( i = 0; i < length; i++ ) {
    n = rand() % l;
    s += charset[n];
  }
  return s;
}

function base64_decode( str, key_str ) {

  local_var len, i, j, k, ret, base64, b64, a, b, c, o, str, key_str;

  if( isnull( str ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#str#-#base64_decode" );

  len = strlen( str );
  ret = "";

  if( key_str )
    base64 = key_str;
  else
    base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  for( i = 0; i < 256; i++ )
    b64[i] = 0;
  for( i = 0; i < strlen( base64 ); i++ )
    b64[ord( base64[i] )] = i;

  for( j = 0; j < len; j += 4 ) {
    for( i = 0; i < 4; i++ ) {
      c = ord( str[j+i] );
      a[i] = c;
      b[i] = b64[c];
    }

    o[0] = ( b[0] << 2 ) | ( b[1] >> 4 );
    o[1] = ( b[1] << 4 ) | ( b[2] >> 2 );
    o[2] = ( b[2] << 6 ) | b[3];
    if( a[2] == ord( '=' ) ) {
     i = 1;
    } else if( a[3] == ord( '=' ) ) {
     i = 2;
    } else {
     i = 3;
    }
    for( k = 0; k < i; k++ )
      ret += raw_string( int( o[k] ) & 255 );

    if( i < 3 )
      break;
  }

  return ret;
}

function base64_code( c ) {

  local_var c, __base64_code;

  __base64_code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  if( isnull( c ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#c#-#base64_code" );

  return( __base64_code[c] );
}

function pow2( x ) {

  local_var __ret, x;

  if( isnull( x ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#x#-#pow2" );

  __ret = 1;
  while( x ) {
    __ret = __ret * 2;
    x = x  - 1;
  }
  return( __ret );
}

function base64( str ) {

  local_var len, i, ret, char_count, _bits, val, cnt, mul, str;

  if( isnull( str ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#str#-#base64" );

  len = strlen( str );
  i = 0;
  ret = "";
  char_count = 0;
  _bits = 0;

  while( i < len ) {
    _bits = _bits + ord( str[i] );
    char_count = char_count + 1;
    if( char_count == 3 ) {
      val = _bits / 262144;
      ret = string( ret, base64_code( c:val ) );
      val = _bits / 4096;
      val = val & 0x3F;
      ret = string( ret, base64_code( c:val ) );
      val = _bits / 64;
      val = val & 0x3F;
      ret = string( ret, base64_code( c:val ) );
      val = _bits & 0x3F;
      ret = string( ret, base64_code( c:val ) );
      char_count = 0;
      _bits = 0;
    } else {
      _bits = _bits * 256;
    }
    i = i + 1;
  }

  if( ! ( char_count == 0 ) ) {
    cnt = char_count * 8;
    mul = 16;
    mul = mul - cnt;
    mul = pow2( x:mul );
    _bits = _bits * mul;
    val = _bits / 262144;
    ret = string( ret, base64_code( c:val ) );
    val = _bits / 4096;
    val = val & 0x3F;
    ret = string( ret, base64_code( c:val ) );
    if( char_count == 1 ) {
      ret = string(ret, "==");
    } else {
      val = _bits / 64;
      val = val & 0x3F;
      ret = string( ret, base64_code( c:val ), "=" );
    }
  }
  return( ret );
}


# This function converts a string representing a decimal number to
# to hexadecimal; eg, dec2hex(1098757090) == "417db3e2".
#
# Args:
#   o num, decimal number.
#
# Return:
#   hex number represented as a raw string.
#
# updated: 16-Nov-2004, George A. Theall
#
function dec2hex( num ) {

  local_var digits, hex, rem, num;

  if( isnull ( num ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#num#-#dec2hex" );

  hex = "";

  num = int( num );
  while( num > 0 ) {
    rem = num % 256;
    hex = raw_string( rem, hex );
    num = num / 256;
    if( num > 0 && num < 255 ) {
      hex = raw_string( num, hex );
      num = 0;
    }
  }
  if( ! hex ) hex = raw_string( 0x00 );

  return hex;
}

# Convert a Date CVS field to Unix time
# Michel Arboi
function cvsdate2unixtime( date ) {

  local_var v, u, date;

  if( ! date ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#date#-#cvsdate2unixtime" );

  v = eregmatch( string:date, pattern:".Date: ([0-9]+)/([01][0-9])/([0-3][0-9]) ([0-2][0-9]):([0-6][0-9]):([0-6][0-9]) \$" );
  if( isnull( v ) ) return;
  u = mktime( year:v[1], mon:v[2], mday:v[3], hour:v[3], min:v[5], sec:v[6] );
  return u;
}

# from packeteer_web_login.nasl
function hex2str() {

  local_var xlat, hs, s, i, j;

  hs = _FCT_ANON_ARGS[0];

  if( isnull( hs ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#hex2str" );
    return;
  }

  s = "";
  for( i = 0; i < 256; ++i )
    xlat[ tolower( substr( hex( i ), 2 ) ) ] = raw_string( i );

  for( j = 0; j < strlen( hs ) / 2; ++j )
    s += xlat[ tolower( substr( hs, 2 * j, 2 * j + 1 ) ) ];

  return s;
}

# "if( is_printer_mac( mac:mac ) ) do something..."
# include mac_prefix.inc if you want to use this function
function is_printer_mac( mac ) {

  local_var mac, mac_s, p_vendors, max_prefix, mac_vendor, _pv;

  if( ! mac ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#mac#-#is_printer_mac" );
    return;
  }

  mac_s = split( mac, sep:":", keep:FALSE );
  if( max_index( mac_s ) != 6 ) return;

  p_vendors = make_list( "xerox", "canon", "kyocera", "lexmark", "hewlettp", "samsung" );

  mac_prefix = toupper( mac_s[0] + ':' + mac_s[1] + ':' + mac_s[2] );

  mac_vendor = tolower( mac_prefixes[ mac_prefix ] );
  if( ! mac_vendor ) return;

  foreach _pv( p_vendors )
    if( mac_vendor == _pv )
      return TRUE;

  return;
}

# @brief Removes any non-printable characters in a passed data/string (default) or replaces
#        it with a specified replacement string passed to this function.
#
# @param ddata               The data to evaluate.
# @param noprint_replacement An (optional) char/string to be use to replace the non-printable
#                            chars with. If not passed the non-printable char will be removed
#                            instead.
#
# @return A string with the removed/replaced non-printable chars or NULL if no ddata parameter
#         was passed.
#
function bin2string( ddata, noprint_replacement ) {

  local_var ddata, noprint_replacement;
  local_var tmp, i, j, linenumber, len, data, c;

  if( isnull( ddata ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ddata#-#bin2string" );
    return NULL;
  }

  len = strlen( ddata );
  linenumber = len / 16;

  for( i = 0; i <= linenumber; i++ ) {

    data = "";

    for( j = 0; j < 16; j++ ) {
      if( ( i*16+j ) < len ) {
        c = ddata[i*16+j];

        if( isprint( c:c ) ) {
          data += c;
        } else {
          if( ! isnull( noprint_replacement ) ) {
            data += noprint_replacement;
          }
        }
      }
   }
   tmp += string( data );
  }
  return tmp;
}

# modified unicode4 from smb_nt.inc
function ascii2unicode( data ) {

  local_var data, len, ret, i;

  if( isnull( data ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#ascii2unicode" );
    return;
  }

  len = strlen( data );

  for( i = 0; i < len; i++ ) {
    ret += data[i] + raw_string( 0x00 );
  }
  return ret;
}

# @brief Creates a formatted and sorted table (with two columns) from
#        the info given in the passed array. All array keys are
#        included in the first column and the matching array values
#        in the second column.
#
# @param array        The array to use as a base for the formatted table.
# @param sep          A (optional) separator which should be used between
#                     each column. Defaults to " : " if not given.
# @param columnheader The (optional) headers which should be included above
#                     each column. This needs to be passed in form of a list
#                     like e.g. columnheader:make_list("Column 1", "Column 2");
# @param maxentries   An (optional) amount of entries of the array which should
#                     be included in the created table.
#
# @return A string with the formatted and sorted table or NULL if
#         no array was given.
#
function text_format_table( array, sep, columnheader, maxentries ) {

  local_var array, sep, columnheader, maxentries;
  local_var currententries, _key, len, maxlen, hascolumnheader, columnheaderlen, fulllen, seplen, value, flen, paddinglen, report, reportheader, reportheaderlen;

  if( ! array ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#array#-#text_format_table" );
    return;
  }

  if( ! is_array( array ) ) {
    set_kb_item( name:"nvt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#text_format_table: No array passed in 'array' parameter" );
    return;
  }

  if( isnull( sep ) )
    sep = " : ";

  currententries = 0;
  foreach _key( sort( keys( array ) ) ) {

    currententries++;
    if( maxentries > 0 && currententries > maxentries )
      break;

    _key = chomp( _key );
    _key = ereg_replace( string:_key, pattern:'[\r\n]+', replace:"<newline>" );
    len = strlen( _key );

    if( ! maxlen ) {
      maxlen = len;
      continue;
    }

    if( maxlen < len )
      maxlen = len;
  }

  if( columnheader && is_array( columnheader ) ) {
    hascolumnheader = TRUE;
    columnheaderlen = strlen( chomp( columnheader[0] ) );
    if( maxlen < columnheaderlen )
      maxlen = columnheaderlen;
  }

  currententries = 0;
  fulllen = 0;
  seplen = strlen( sep );
  foreach _key( sort( keys( array ) ) ) {

    currententries++;
    if( maxentries > 0 && currententries > maxentries )
      break;

    value = array[_key]; # nb: This needs to be placed before the chomp() on _key because the it wouldn't match anything afterwards.
    _key = chomp( _key );
    _key = ereg_replace( string:_key, pattern:'[\r\n]+', replace:"<newline>" );
    flen = strlen( _key );
    paddinglen = ( maxlen - flen );
    value = chomp( value );
    value = ereg_replace( string:value, pattern:'[\r\n]+', replace:"<newline>" );
    valuelen = strlen( value );

    report += _key + crap( data:" ", length:paddinglen ) + sep + value + '\n';

    if( valuelen + maxlen > fulllen )
      fulllen = maxlen + valuelen;
  }

  if( strlen( report ) ) {
    if( hascolumnheader ) {

      reportheader = chomp( columnheader[0] ) + crap( data:" ", length:maxlen - columnheaderlen ) + sep + chomp( columnheader[1] ) + '\n';
      reportheaderlen = strlen( reportheader ) - 1; # nb: -1 for the '\n'

      if( fulllen + seplen < reportheaderlen )
        fulllen = reportheaderlen;
      else
        fulllen += seplen;

      reportheader += crap( data:"-", length:fulllen ) + '\n';
      report = reportheader + report;
    }
    return chomp( report );
  }
}

function eol_date_reached( eol_date ) {

  local_var eol_date, local_time;

  if( ! eol_date ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_date#-#eol_date_reached" );
    return;
  }

  # Special case to mark an OS/Product as EOL if the date is unknown.
  # This avoids that we need to guess a date for e.g. older products.
  if( eol_date == "unknown" ) return TRUE;

  eol_date = str_replace( string:eol_date, find:"-", keep:FALSE );
  local_time = make_date_str( date:localtime( unixtime() ) );

  if( int( local_time ) >= int( eol_date ) )
    return TRUE;

  return;
}

function build_eol_message( eol_type, name, cpe, version, location, skip_version, eol_version, eol_date, eol_url ) {

  local_var eol_type, name, cpe, version, location, skip_version, eol_version, eol_date, eol_url;
  local_var report;

  if( eol_type != "prod" && eol_type != "os" ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#build_prod_eol_message: Wrong value passed to eol_type. Valid values are: prod, os" );
    return "";
  }

  if( eol_type == "prod" ) {

    if( ! name )
      set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#build_eol_message" );

    if( ! cpe )
      set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#build_eol_message" );

    if( ! version && ! skip_version )
      set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#build_eol_message" );

    if( ! eol_version && ! skip_version )
      set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_version#-#build_eol_message" );

    if( ! eol_date )
      set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_date#-#build_eol_message" );

    if( ! skip_version ) {
      report = 'The "' + name + '" version on the remote host has reached the end of life.\n\n' +
               'CPE:               ' + cpe + ':' + version + '\n' +
               'Installed version: ' + version;
    } else {
      report = 'The "' + name + '" product on the remote host has reached the end of life.\n\n' +
               'CPE:               ' + cpe;
    }

    if( location )
      report += '\nLocation/URL:      ' + location;

    if( eol_version )
      report += '\nEOL version:       ' + eol_version;

    if( eol_date )
      report += '\nEOL date:          ' + eol_date;

    if( eol_url )
      report += '\nEOL info:          ' + eol_url;

  } else if( eol_type == "os" ) {

    if( ! name )
      set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#build_eol_message" );

    if( ! cpe )
      set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#build_eol_message" );

    if( ! eol_date )
      set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_date#-#build_eol_message" );

    if( ! eol_url )
      set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_url#-#build_eol_message" );

    report = 'The "' + name + '" Operating System on the remote host has reached the end of life.\n\n' +
             'CPE:               ' + cpe;

    if( version && version != "unknown" ) {
      report += '\nInstalled version,\n';
      report += 'build or SP:       ' + version;
    }

    if( eol_version )
      report += '\nEOL version:       ' + eol_version;

    if( eol_date )
      report += '\nEOL date:          ' + eol_date;

    if( eol_url )
      report += '\nEOL info:          ' + eol_url;
  }
  return report;
}

# @brief Converts a passed date string generated by the unixtime() function
#        into a form like 20180813
#
# @param date a date string generated by the unixtime() function
#
# @todo Merge the functionality of make_date_str() in 2013/gb_host_scanned_wmi.nasl
#       and 2013/gb_host_scanned_ssh.nasl into this function.
#
# @return A string containing the current date in the form of 20180813 or NULL
#         if no date parameter was passed.
#
function make_date_str( date ) {

  local_var date, time, month, day;

  if( isnull( date ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#date#-#make_date_str" );
    return;
  }

  time  = localtime( date );
  month = fancy_date( datestr:time["mon"]  );
  day   = fancy_date( datestr:time["mday"] );

  # Using string to make sure we return a string and don't do an addition of ints
  return string( time["year"], month, day );
}

# @brief Adds a leading 0/zero to a passed numeric string if the value is < 10
#        and returns the string back.
#
# @todo Merge the functionality of fancy_date() in 2013/gb_host_scanned_wmi.nasl,
#       2013/gb_host_scanned_ssh.nasl, gb_nist_win_oval_sys_char_generator.nasl
#       and kb_2_sc.nasl into this function.
#
# @param datastr the numeric string to evaluate
#
# @return a string with a leading 0 if the passed string was < 10, the same string
#         otherwise and NULL if no datestr parameter was passed.
#
function fancy_date( datestr ) {

  local_var datestr;

  if( isnull( datestr ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#datestr#-#fancy_date" );
    return;
  }

  if( int( datestr ) < 10 )
    return string( "0", datestr );
  else
    return datestr;
}

# @brief Creates an array of the commands 'ipconfig' and 'id' as the array key and the regex to match
#        against the response of these commands as the array value. The function will chose the
#        returned commands if the remote system is running on Windows, Linux or if the OS is unknown.
#
# @param _FCT_ANON_ARGS[0] Allows (optional) to pass either "windows" or "linux" as an anonymous function parameter
#                          to define directly which kind of files should be returned.
#
# @note Add a dependency to os_detection.nasl if you want to use this function. The VT calling this
#       function needs to also include host_details.inc (for host_runs());
#
# @return An array as described in the function summary.
#
function exploit_commands() {

  local_var res;

  if( _FCT_ANON_ARGS[0] ) {

    if( tolower( _FCT_ANON_ARGS[0] ) == "windows" ) {
      res = "yes";
    } else if( tolower( _FCT_ANON_ARGS[0] ) == "linux" ) {
      res = "no";
    }
  } else {
    res = host_runs( "windows" );
  }

  if( res == "yes" ) {
    return make_array( "Windows.IP..onfiguration", "ipconfig" );
  } else if( res == "no" ) {
    return make_array( "uid=[0-9]+.*gid=[0-9]+", "id" );
  }

  # unknown
  return make_array( "uid=[0-9]+.*gid=[0-9]+", "id",
                     "Windows.IP..onfiguration", "ipconfig" );
}

# @brief Creates an array of common files to check during "Path traversal" attacks. The array contains the
#        the regex to match against the expected content of these files as the array key and the file to check
#        as the array value. The function will chose the returned files if the remote system is running on
#        Windows, Linux or if the OS is unknown.
#
# @param _FCT_ANON_ARGS[0] Allows (optional) to pass either "windows" or "linux" as an anonymous function parameter
#                          to define directly which kind of files should be returned.
#
# @note Add a dependency to os_detection.nasl if you want to use this function.
#
# @return An array as described in the function summary.
#
function traversal_files() {

  local_var res;

  if( _FCT_ANON_ARGS[0] ) {

    if( tolower( _FCT_ANON_ARGS[0] ) == "windows" ) {
      res = "yes";
    } else if( tolower( _FCT_ANON_ARGS[0] ) == "linux" ) {
      res = "no";
    }
  } else {
    res = host_runs( "windows" );
  }

  if( res == "yes" ) {
    return make_array( "\[boot loader\]", "boot.ini",
                       "; for 16-bit app supporT", "winnt/win.ini",
                       "; for 16-bit app support", "windows/win.ini" );
  } else if( res == "no" ) {
    return make_array( "root:.*:0:[01]:", "etc/passwd" ); # TBD: Also check e.g. etc/hosts for basic IDS?
  }

  # "unknown"
  return make_array( "root:.*:0:[01]:", "etc/passwd",
                     "\[boot loader\]", "boot.ini",
                     "; for 16-bit app supporT", "winnt/win.ini",
                     "; for 16-bit app support", "windows/win.ini" );
}

# @brief Gets the hostname of the target via get_host_name() and
#        if no IPv4/IPv6 address was returned by this function it
#        returns a list containing the parts of the target hostname.
#
#        For example a hostname of www.example.com returns a list containing
#        the following:
#        1 -> www
#        2 -> example
#        3 -> com
#        4 -> www.example
#        5 -> www.example.com
#        6 -> example.com
#        7 -> com.example
#        8 -> com.example.www
#
# @todo We currently can't catch a example.com from www.sub.example.com
#
# @return a list containing the parts of the target hostname, an empty list
#         if get_host_name() returned an IPv4/IPv6 address.
#
function create_hostname_parts_list() {

  local_var list, hnlist, hn, hnp, hnl, p, parts, i;

  list = make_list();

  # Available since GVM-10 / git commit 4ba1a59
  if( defined_func( "get_host_names" ) )
    hnlist = get_host_names();
  else
    hnlist = make_list( get_host_name() );

  foreach hn( hnlist ) {

    # nb: We don't want to add an IPv4/IPv6 address here...
    if( ":" >!< hn && ! ereg( string:hn, pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" ) ) {

      hnp = split( hn, sep:".", keep:FALSE );
      hnl = max_index( hnp );

      parts = "";
      for( i = 0; i < hnl; i++ ) {
        # each single entry on its own
        list = make_list( list, hnp[i] );
        # concatenate each entry with the previous one
        parts += "." + hnp[i];
        parts = ereg_replace( pattern:"^\.", string:parts, replace:'' );
        if( ! in_array( search:parts, array:list ) )
          list = make_list( list, parts );
      }

      parts = "";
      for( i = 1; i < hnl; i++ ) {
        # This is a special case to skip the first part like www from www.example.com
        parts += "." + hnp[i];
        parts = ereg_replace( pattern:"^\.", string:parts, replace:'' );
        if( ! in_array( search:parts, array:list ) )
          list = make_list( list, parts );
      }

      parts = "";
      for( i = hnl - 1; i >= 0; i-- ) {
        # concatenate each entry with the previous one
        parts += "." + hnp[i];
        parts = ereg_replace( pattern:"^\.", string:parts, replace:'' );
        if( ! in_array( search:parts, array:list ) )
          list = make_list( list, parts );
      }
    }
  }
  return list;
}

# @brief Checks if the NVT calling this function is executed on a Greenbone OS (GOS).
#
# @return TRUE if executed on a GOS, FALSE if not executed on a GOS and NULL if the
#              function vendor_version() needed for this check is missing (e.g. running
#              a GOS/GVM/OpenVAS installation not providing this function yet).
#
function executed_on_gos() {

  if( ! defined_func( "vendor_version" ) ) return NULL;

  if( vendor_version() =~ "^Greenbone OS" ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

# @brief Tries to detect the local Greenbone OS (GOS) version of the NVT calling this function.
#
# @return The version number as a string if executed on a GOS and it was possible to gather the version,
#         FALSE if not executed on a GOS and NULL if it was not possible to gather the version.
#
function get_local_gos_version() {

  local_var result;

  if( isnull( executed_on_gos() ) ) {
    return NULL;
  } else if( ! executed_on_gos() ) {
    return FALSE;
  } else {
    result = eregmatch( pattern:"([0-9.]+)$", string:vendor_version() );
    return result[1];
  }
}

# @brief Returns an array containing various representations of a Vulnerability Test (VT) string which can
#        be used in VTs as e.g. a user name.
#
# @note The returned string depends on the platform (OpenVAS/GVM/GOS) the scanner is running at.
#
# @return An array containing various string representations of either "GBNVT" or "OpenVASVT"
#         depending on the platform the scanner is running at. Currently the following array indices
#         are supported / available:
#
#         ret_array["default"]             = either "GBNVT" or "OpenVASVT"
#         ret_array["default_rand"]        = "default" with random numbers appended
#         ret_array["default_hex"]         = "default" converted to a hex string
#         ret_array["default_rand_hex"]    = "default_rand" converted to a hex string
#         ret_array["default_ver_space"]   = "default" with the current library version appended and a space as a separator
#         ret_array["default_ver_dash"]    = "default" with the current library version appended and a dash as a separator
#         ret_array["default_dash"]        = "default" with a dash ("-"), e.g. "GBN-VT" or "OpenVAS-VT"
#         ret_array["default_rand_dash"]   = "default" with a dash with random numbers appended
#
#         ret_array["ping_string"] = either "GBNVT" or "OpenVASVT" in a form of e.g. "_GBNVT1234_" filled up to 16 bytes of total length, for the use in the "-p" parameter of unixoide ping commands which allows a max. of 16 bytes in the passed string
#
#         ret_array["lowercase"]           = either "gbn-vt" or "openvas-vt"
#         ret_array["lowercase_rand"]      = "lowercase" with random numbers appended
#         ret_array["lowercase_hex"]       = "lowercase" converted to a hex string
#         ret_array["lowercase_rand_hex"]  = "lowercase_rand" converted to a hex string
#         ret_array["lowercase_ver_space"] = "lowercase" with the current library version appended and a space as a separator
#         ret_array["lowercase_ver_dash"]  = "lowercase" with the current library version appended and a dash as a separator
#         ret_array["lowercase_dash"]      = "lowercase" with a dash ("-"), e.g. "GBN-VT" or "OpenVAS-VT"
#         ret_array["lowercase_rand_dash"] = "lowercase" with a dash with random numbers appended
#
#         ret_array["uppercase"]           = either "GBN-VT" or "OPENVAS-VT"
#         ret_array["uppercase_rand"]      = "uppercase" with random numbers appended
#         ret_array["uppercase_hex"]       = "uppercase" converted to a hex string
#         ret_array["uppercase_rand_hex"]  = "uppercase_rand" converted to a hex string
#         ret_array["uppercase_ver_space"] = "uppercase" with the current library version appended and a space as a separator
#         ret_array["uppercase_ver_dash"]  = "uppercase" with the current library version appended and a dash as a separator
#         ret_array["uppercase_dash"]      = "uppercase" with a dash ("-"), e.g. "GBN-VT" or "OpenVAS-VT"
#         ret_array["uppercase_rand_dash"] = "uppercase" with a dash with random numbers appended
#
function get_vt_strings() {

  local_var ret_array, vt_string, vt_string_dash, vt_string_lo, vt_string_up, rand_numbers, version;

  ret_array = make_array();

  if( executed_on_gos() ) {
    vt_string = "GBNVT";
    vt_string_dash = "GBN-VT";
  } else {
    vt_string = "OpenVASVT";
    vt_string_dash = "OpenVAS-VT";
  }

  if( OPENVAS_VERSION )
    version = OPENVAS_VERSION;
  else
    version = "1.0"; # nb: Just as a fallback if OPENVAS_VERSION isn't defined somehow.

  vt_string_lo = tolower( vt_string );
  vt_string_up = toupper( vt_string );
  vt_string_dash_lo = tolower( vt_string_dash );
  vt_string_dash_up = toupper( vt_string_dash );
  rand_numbers = string( rand() ); # nb: Returns an integer with a length between 9 and 10, converting it to string first

  ret_array["default"] = vt_string;
  ret_array["default_rand"] = vt_string + rand_numbers;
  ret_array["default_hex"] = hexstr( vt_string );
  ret_array["default_rand_hex"] = hexstr( vt_string + rand_numbers );
  ret_array["default_ver_space"] = vt_string + " " + version;
  ret_array["default_ver_dash"] = vt_string + "-" + version;
  ret_array["default_dash"] = vt_string_dash;
  ret_array["default_rand_dash"] = vt_string_dash + rand_numbers;

   # nb: e.g. for the use in the "-p" parameter of unixoide ping commands which allows a max. of 16 bytes in the passed string
  ret_array["ping_string"] = "_" + vt_string + substr( rand_numbers, 0, 16 - strlen( vt_string ) - 3 ) + "_";

  ret_array["lowercase"] = vt_string_lo;
  ret_array["lowercase_rand"] = vt_string_lo + rand_numbers;
  ret_array["lowercase_hex"] = hexstr( vt_string_lo );
  ret_array["lowercase_rand_hex"] = hexstr( vt_string_lo + rand_numbers );
  ret_array["lowercase_ver_space"] = vt_string_lo + " " + version;
  ret_array["lowercase_ver_dash"] = vt_string_lo + "-" + version;
  ret_array["lowercase_dash"] = vt_string_dash_lo;
  ret_array["lowercase_rand_dash"] = vt_string_dash_lo + rand_numbers;

  ret_array["uppercase"] = vt_string_up;
  ret_array["uppercase_rand"] = vt_string_up + rand_numbers;
  ret_array["uppercase_hex"] = hexstr( vt_string_up );
  ret_array["uppercase_rand_hex"] = hexstr( vt_string_up + rand_numbers );
  ret_array["uppercase_ver_space"] = vt_string_up + " " + version;
  ret_array["uppercase_ver_dash"] = vt_string_up + "-" + version;
  ret_array["uppercase_dash"] = vt_string_dash_up;
  ret_array["uppercase_rand_dash"] = vt_string_dash_up + rand_numbers;

  return ret_array;
}
