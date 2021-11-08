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
  script_oid("1.3.6.1.4.1.25623.1.0.150417");
  script_version("2020-11-20T12:35:19+0000");
  script_tag(name:"last_modification", value:"2020-11-20 12:35:19 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-20 10:52:10 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("GaussDB Kernel: Documenting Extensions");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_gaussdb_kernel_ssh_login_detect.nasl", "gaussdbkernel_authentication_information.nasl");
  script_mandatory_keys("huawei/gaussdb_kernel/detected", "Compliance/Launch");

  script_tag(name:"summary", value:"All installed extensions must be documented. You need to carefully check any
unidentified extensions.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd = "SELECT extname, extversion FROM pg_extension where EXTNAME not in ('plpgsql', 'dist_fdw', 'file_fdw', 'roach_api', 'hdfs_fdw', 'gc_fdw', 'log_fdw', 'hstore', 'packages', 'dimsearch', 'uuid-ossp', 'tsdb', 'security_plugin');";
title = "Documenting Extensions";
solution = "DELETE FROM pg_extension where EXTNAME not in ('plpgsql', 'dist_fdw', 'file_fdw', 'roach_api', 'hdfs_fdw', 'gc_fdw', 'log_fdw', 'hstore', 'packages', 'dimsearch', 'uuid-ossp', 'tsdb', 'security_plugin');";
default = "none";
test_type = "SQL_Query";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if ( ! value = policy_gsql_cmd( socket:sock, query:cmd, db_type:"gaussdbkernel" ) ) {
  compliant = "yes";
  value = "N/A";
}else if ( value =~ "failed to connect" ) {
  compliant = "incomplete";
  value = "error";
  comment = "No connection to database";
}else{
  compliant = "no";
  value = ereg_replace(string:chomp(value), pattern:"^\s+", replace:"");
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );
