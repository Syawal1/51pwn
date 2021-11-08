# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.150404");
  script_version("2020-11-20T09:38:55+0000");
  script_tag(name:"last_modification", value:"2020-11-20 09:38:55 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-20 09:19:53 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("GaussDB Kernel: Authentication Parameters");

  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Compliance");

  script_add_preference(name:"Database", type:"entry", value:"postgres", id:1);
  script_add_preference(name:"Port", type:"entry", value:"8000", id:2);

  script_tag(name:"summary", value:"Set login parameters for scanning GaussDB Kernel database.");

  exit(0);
}

database = script_get_preference( "Database", id:1 );
if ( database && database != "" )
  set_kb_item( name:"Policy/gaussdbkernel/database", value:database );
else
  set_kb_item( name:"Policy/gaussdbkernel/database", value:"postgres" );

port = script_get_preference( "Port", id:2 );
if ( port && port != "" )
  set_kb_item( name:"Policy/gaussdbkernel/port", value:port );
else
  set_kb_item( name:"Policy/gaussdbkernel/port", value:"8000" );

exit(0);