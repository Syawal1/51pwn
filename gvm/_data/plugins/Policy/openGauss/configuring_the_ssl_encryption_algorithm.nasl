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
  script_oid("1.3.6.1.4.1.25623.1.0.150352");
  script_version("2020-11-12T15:07:01+0000");
  script_tag(name:"last_modification", value:"2020-11-12 15:07:01 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-11 15:21:37 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("openGauss: Configuring the SSL Encryption Algorithm");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_huawei_opengauss_ssh_login_detect.nasl", "compliance_tests.nasl", "opengauss_authentication_information.nasl");
  script_mandatory_keys("huawei/opengauss/detected", "Compliance/Launch");

  script_xref(name:"URL", value:"https://opengauss.org");

  script_tag(name:"summary", value:"ssl_ciphers specifies the SSL encryption algorithms used for secure connections.
openGauss supports the following algorithms:

  - DHE-RSA-AES256-GCM-SHA384

  - DHE-RSA-AES128-GCM-SHA256

  - DHE-DSS-AES256-GCM-SHA384

  - DHE-DSS-AES128-GCM-SHA256

  - DHE-RSA-AES256-SHA256

  - DHE-RSA-AES128-SHA256

  - DHE-DSS-AES256-SHA256

  - DHE-DSS-AES128-SHA256

  - DHE-RSA-AES256-CCM

  - DHE-RSA-AES128-CCM

  - DHE-RSA-AES256-SHA

  - DHE-RSA-AES128-SHA

  - DHE-DSS-AES256-SHA

  - DHE-DSS-AES128-SHA

You are advised to set ssl_ciphers to ALL. Then, openGauss uses DHE-RSA-AES256-GCM-SHA384 by default.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd = "SELECT name,setting FROM pg_settings WHERE name='ssl_ciphers';";
title = "Configuring the SSL Encryption Algorithm";
solution = "Set ssl_ciphers to ALL in the postgresql.conf file and then restart the database.";
default = "ALL";
test_type = "SQL_Query";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if ( ! value = policy_gsql_cmd( socket:sock, query:cmd ) ) {
  compliant = "incomplete";
  value = "error";
  comment = "SQL command did not return anything";
}else if ( value =~ "failed to connect" ) {
  compliant = "incomplete";
  value = "error";
  comment = "No connection to database";
}else{
  value = ereg_replace( string:chomp(value), pattern:"^\s+", replace:"" );
  setting = eregmatch( string:value, pattern:"ssl_ciphers\s+\|\s+(.+)" );
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
