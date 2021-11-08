# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109715");
  script_version("2020-11-03T12:34:25+0000");
  script_tag(name:"last_modification", value:"2020-11-03 12:34:25 +0000 (Tue, 03 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-01-09 08:27:15 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Mounting of freevxfs filesystems");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_lsmod_kernel_modules.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Status", type:"radio", value:"Disabled;Enabled", id:1);

  script_tag(name:"summary", value:"The freevxfs filesystem type is a free version of the Veritas
type filesystem. This is the primary filesystem type for HP-UX operating systems.

Removing support for unneeded filesystem types reduces the local attack surface of the system. If
this filesystem type is not needed, disable it.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");

cmd = "lsmod; grep -r 'install freevxfs /bin/true' /etc/modprobe.d/*";
title = "Mounting of freevxfs filesystems";
solution = "Edit or create a file in the /etc/modprobe.d/ directory ending in .conf and add the following line:
'install freevxfs /bin/true'.
Run the following command to unload the freevxfs module: 'rmmod freevxfs'.";
test_type = "SSH_Cmd";
default = script_get_preference("Status", id:1);
default = "Disabled";

if( ! modprobe = policy_modprobe( module:"freevxfs" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run modprobe command on host";
}else if( get_kb_item( "Policy/linux/lsmod/ERROR" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run lsmod command on host";
}else{
  if( get_kb_item("Policy/linux/module/freevxfs" ) ) {
    loaded = TRUE;
    comment = "Kernel module freevxfs loaded. ";
  }

  if( modprobe !~ "install /bin/true" ){
    no_install_redirect = TRUE;
    comment += "Kernel module freevxfs is not configured to run '/bin/true'.";
  }

  if(loaded || no_install_redirect)
    value = "Enabled";
  else
    value = "Disabled";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
