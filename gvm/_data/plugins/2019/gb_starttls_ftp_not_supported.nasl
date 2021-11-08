# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108553");
  script_version("$Revision: 13863 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 08:07:42 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-26 08:10:03 +0100 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FTP Missing Support For AUTH TLS");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("gb_starttls_ftp.nasl");
  script_mandatory_keys("ftp/starttls/not_supported");

  script_tag(name:"summary", value:"The remote FTP server does not support the 'AUTH TLS' command.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "ftp/starttls/not_supported/port" );
if( ! port )
  exit( 99 );

log_message( port:port, data:"The remote FTP server does not support the 'AUTH TLS' command." );
exit( 0 );