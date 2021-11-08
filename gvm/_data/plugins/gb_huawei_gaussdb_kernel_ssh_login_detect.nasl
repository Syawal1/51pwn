# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108977");
  script_version("2020-10-27T08:14:35+0000");
  script_tag(name:"last_modification", value:"2020-10-27 08:14:35 +0000 (Tue, 27 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-27 07:38:45 +0000 (Tue, 27 Oct 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Huawei GaussDB Kernel Detection (SSH-Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login based detection of Huawei GaussDB Kernel.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

port = kb_ssh_transport();
found = FALSE;
bins = make_list();
found_installs = make_array();

# nb: gaussdb is the database server program, gsql is the client program. Normally both should exist on
# a default setup but we still want to try the client program if the database server program wasn't found.
# The idea is basically to save the install path into an array as the array key and the version into the
# array value so that we're not reporting multiple installations for a single one where both binaries are
# accessible.
_bins = ssh_find_file( file_name:"/gaussdb", useregex:TRUE, regexpar:"$", sock:sock );
if( _bins )
  bins = make_list( bins, _bins );

_bins = ssh_find_file( file_name:"/gsql", useregex:TRUE, regexpar:"$", sock:sock );
if( _bins )
  bins = make_list( bins, _bins );

if( max_index( bins ) < 1 )
  exit( 0 );

foreach bin( bins ) {

  bin = chomp( bin );
  if( ! bin )
    continue;

  # Used to not include the export call below in the install path reporting.
  ld_bin = bin;

  # We need to gather the base path so that we can use it in the array as explained above.
  # In addition on some setups the LD_LIBRARY_PATH isn't configured correctly causing the a
  # failed call of the binary. The path will passed to the get_bin_version below so that we're
  # still able to gather the version info.
  base_path = ereg_replace( string:bin, pattern:"(/s?bin/(gaussdb|gsql))$", replace:"" );

  # nb: Don't append a wrong base_path (including the binary or similar) to the LD_LIBRARY_PATH.
  if( base_path !~ "/(gaussdb|gsql)$" )
    ld_bin = 'export LD_LIBRARY_PATH="' + base_path + '/lib":$LD_LIBRARY_PATH; ' + bin;

  # gaussdb (GaussDB Kernel V500R001C00 build dd19f330) compiled at 2020-07-25 10:31:18 commit 2143 last mr 131
  # gsql (GaussDB Kernel V500R001C00 build dd19f330) compiled at 2020-07-25 10:31:18 commit 2143 last mr 131
  vers = ssh_get_bin_version( full_prog_name:ld_bin, sock:sock, version_argv:"-V", ver_pattern:"\(GaussDB Kernel ([VRCHPS0-9.]+)" );
  if( ! vers || ! vers[1] )
    continue;

  version = vers[1];

  # nb: Avoid multiple reports for the same installation. There might be situations
  # like /usr/local/bin/gaussdb and /usr/local/bin/gsql which have the same version
  # but are different installations but we can't detect something like that at all.
  bin_path = ereg_replace( string:bin, pattern:"(/(gaussdb|gsql))$", replace:"" );
  if( found_installs[bin_path] && found_installs[bin_path] == version )
    continue;

  found_installs[bin_path] = version;
  build = "unknown";

  if( build_match = eregmatch( pattern:"build ([^)]+)\)", string:vers[2] ) )
    build = build_match[1];

  found = TRUE;

  set_kb_item( name:"huawei/gaussdb_kernel/ssh-login/" + port + "/installs", value:"0#---#" + bin + "#---#" + vers[2] + "#---#" + version + "#---#" + build );
}

if( found ) {
  set_kb_item( name:"huawei/gaussdb_kernel/detected", value:TRUE );
  set_kb_item( name:"huawei/gaussdb_kernel/port", value:port );
}

ssh_close_connection();

exit( 0 );
