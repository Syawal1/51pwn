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
  script_oid("1.3.6.1.4.1.25623.1.0.150435");
  script_version("2020-11-20T12:35:19+0000");
  script_tag(name:"last_modification", value:"2020-11-20 12:35:19 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-20 10:52:10 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("GaussDB Kernel: Configuring the Number of Authentication and Encryption Iterations");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_gaussdb_kernel_ssh_login_detect.nasl", "gaussdbkernel_authentication_information.nasl");
  script_mandatory_keys("huawei/gaussdb_kernel/detected", "Compliance/Launch");

  script_tag(name:"summary", value:"Configure the number of iterations during the generation of encryption
information for authentication.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd = "SELECT name,setting FROM pg_settings WHERE name = 'auth_iteration_count';";
title = "Configuring the Number of Authentication and Encryption Iterations";
solution = "Set auth_iteration_count to 10000 in the postgresql.conf file and then restart
the database.";
default = "10000";
test_type = "SQL_Query";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if ( ! value = policy_gsql_cmd( socket:sock, query:cmd, db_type:"gaussdbkernel" ) ) {
  compliant = "incomplete";
  value = "error";
  comment = "SQL command did not return anything";
}else if ( value =~ "failed to connect" ) {
  compliant = "incomplete";
  value = "error";
  comment = "No connection to database";
}else{
  value = ereg_replace( string:chomp( value ), pattern:"^\s+", replace:"" );
  setting = eregmatch( string:value, pattern:"auth_iteration_count\s+\|\s+(.+)" );
  if( ! setting[1] ){
    compliant = "incomplete";
    comment = "Can not determine setting.";
  }else{
    compliant = policy_setting_exact_match( value:setting[1], set_point:default );
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );
