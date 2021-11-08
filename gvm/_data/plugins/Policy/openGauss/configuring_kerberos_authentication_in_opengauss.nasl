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
  script_oid("1.3.6.1.4.1.25623.1.0.150353");
  script_version("2020-11-23T15:39:06+0000");
  script_tag(name:"last_modification", value:"2020-11-23 15:39:06 +0000 (Mon, 23 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-23 15:13:18 +0000 (Mon, 23 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("openGauss: Configuring Kerberos Authentication in openGauss");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_huawei_opengauss_ssh_login_detect.nasl", "compliance_tests.nasl");
  script_mandatory_keys("huawei/opengauss/detected", "Compliance/Launch");

  script_xref(name:"URL", value:"https://opengauss.org");

  script_tag(name:"summary", value:"Use gs_om to enable and disable Kerberos authentication in openGauss.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd = "After the command is executed, a success message is displayed.
In addition, you can view the pg_hba.conf configuration file in the data directory
of a database node to check whether the authentication mode of nodes in
openGauss is gss, that is, whether Kerberos authentication is enabled.";
title = "Configuring Kerberos Authentication in openGauss";
solution = "Ensure that openGauss is running properly.
Run the following command. USER indicates the initial user of openGauss. The
command line with --krb-server is executed on the primary database node, and
the command line with --krb-client is executed on all nodes.
gs_om -t kerberos -m install -U USER --krb-server
gs_om -t kerberos -m install -U USER --krb-client
After all commands are successfully executed, restart the database service and
enable Kerberos authentication in openGauss.
gs_om -t stop
gs_om -t start";
default = "gss";
test_type = "Manual Check";

if( ! get_kb_item( "login/SSH/success" ) ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else{
  compliant = "incomplete";
  value = "None";
  comment = "Please check the value manually.";
}


policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );