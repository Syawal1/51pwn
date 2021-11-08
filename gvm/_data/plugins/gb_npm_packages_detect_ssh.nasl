# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108456");
  script_version("2020-06-22T08:41:58+0000");
  script_tag(name:"last_modification", value:"2020-06-22 08:41:58 +0000 (Mon, 22 Jun 2020)");
  script_tag(name:"creation_date", value:"2018-08-08 13:22:34 +0200 (Wed, 08 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("npm Packages Detection (SSH-Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.npmjs.com/");

  script_tag(name:"summary", value:"This script performs SSH login based detection of packages
  installated by the npm package manager.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");

function register_npms( buf, location ) {
  local_var buf, location;
  set_kb_item( name:"ssh/login/npm_packages/locations", value:location );
  set_kb_item( name:"ssh/login/npm_packages" + location, value:buf );
}

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

locations = ssh_find_file( file_name:"/node_modules", useregex:TRUE, regexpar:"$", sock:sock );

foreach location( locations ) {

  location = chomp( location );
  if( ! location || location =~ "^/usr/share" || # nb: This is the "global" installation location
      location =~ "/node_modules/.+/node_modules" ) # nb: To avoid catching something like e.g. /usr/share/npm/node_modules/sha/node_modules, we only want to catch the "main" directory
    continue;

  buf = ssh_cmd( socket:sock, cmd:"cd " + location + " && COLUMNS=400 npm list" );

  if( buf && buf =~ "^/.+" && "(empty)" >!< buf ) {
    register_npms( buf:buf, location:location );
    found = TRUE;
  }
}

buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 npm list -g" );
if( buf && buf =~ "^/.+" && "(empty)" >!< buf ) {
  register_npms( buf:buf, location:"/global" );
  found = TRUE;
}

if( found )
  set_kb_item( name:"ssh/login/npm_packages/detected", value:TRUE );

ssh_close_connection();
exit( 0 );
