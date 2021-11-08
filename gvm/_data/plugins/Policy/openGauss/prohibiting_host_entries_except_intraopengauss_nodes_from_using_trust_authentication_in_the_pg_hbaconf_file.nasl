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
  script_oid("1.3.6.1.4.1.25623.1.0.150346");
  script_version("2020-11-12T12:33:52+0000");
  script_tag(name:"last_modification", value:"2020-11-12 12:33:52 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-11 15:21:37 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("openGauss: Prohibiting host Entries (Except Intra-openGauss Nodes) from Using Trust Authentication in the pg_hba.conf File");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_huawei_opengauss_ssh_login_detect.nasl", "compliance_tests.nasl");
  script_mandatory_keys("huawei/opengauss/detected", "Compliance/Launch");

  script_xref(name:"URL", value:"https://opengauss.org");

  script_tag(name:"summary", value:"openGauss nodes are deployed on the secure intranet. Only the communications
between intra-openGauss nodes are allowed to use trust authentication. Trust
authentication assumes that all users who can connect to the openGauss server
nodes can access the database. This method is applied only when all users
connecting to the machine are allowed to access the TCP or IP connection of the
Database.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd = "grep -P '^[^#]*host(ssl|nossl)?\s+.+[Tt][Rr][Uu][Ss][Tt]\s*$' ${GAUSSDATA}/pg_hba.conf";
title = "Prohibiting host Entries (Except Intra-openGauss Nodes) from Using Trust Authentication in the pg_hba.conf File";
solution = "Configure non-trust authentication for the host entries (except intra-openGauss
nodes) in the pg_hba.conf file.";
default = "internal nodes";
test_type = "Manual Check";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if ( ! value = ssh_cmd( socket:sock, cmd:cmd ) ) {
  compliant = "incomplete";
  value = "error";
  comment = "The command did not return anything.";
}else{
  compliant = "incomplete";
  comment = "Please check the value manually.";
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );