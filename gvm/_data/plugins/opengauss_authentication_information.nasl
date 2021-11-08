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
  script_oid("1.3.6.1.4.1.25623.1.0.150403");
  script_version("2020-11-12T07:25:50+0000");
  script_tag(name:"last_modification", value:"2020-11-12 07:25:50 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-12 07:11:36 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("openGauss: Authentication Parameters");

  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Compliance");

  script_add_preference(name:"Database", type:"entry", value:"postgres", id:1);
  script_add_preference(name:"Port", type:"entry", value:"26000", id:2);

  script_xref(name:"URL", value:"https://opengauss.org");

  script_tag(name:"summary", value:"Set login parameters for scanning openGauss database.");

  exit(0);
}

database = script_get_preference( "Database", id:1 );
if ( database && database != "" )
  set_kb_item( name:"Policy/opengauss/database", value:database );
else
  set_kb_item( name:"Policy/opengauss/database", value:"postgres" );

port = script_get_preference( "Port", id:2 );
if ( port && port != "" )
  set_kb_item( name:"Policy/opengauss/port", value:port );
else
  set_kb_item( name:"Policy/opengauss/port", value:"26000" );

exit(0);