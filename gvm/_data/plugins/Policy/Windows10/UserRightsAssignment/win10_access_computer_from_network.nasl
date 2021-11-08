# Copyright (C) 2018 Greenbone Networks GmbH
#
# Text descriptions excerpted from a referenced source are
# Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.109113");
  script_version("2019-12-13T11:11:18+0000");
  script_tag(name:"last_modification", value:"2019-12-13 11:11:18 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"creation_date", value:"2018-04-30 09:56:50 +0200 (Mon, 30 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows 10: Access this computer from the network");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_wmi_access.nasl", "smb_reg_service_pack.nasl", "os_detection.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"Administrators, Remote Desktop Users");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment");

  script_tag(name:"summary", value:"The Access this computer from the network policy setting
determines which users can connect to the device from the network. This capability is required by a
number of network protocols, including Server Message Block (SMB)-based protocols, NetBIOS, Common
Internet File System (CIFS), and Component Object Model Plus (COM+).

Users, devices, and service accounts gain or lose the Access this computer from network user right
by being explicitly or implicitly added or removed from a security group that has been granted this
user right. For example, a user account or a machine account may be explicitly added to a custom
security group or a built-in security group, or it may be implicitly added by Windows to a computed
security group such as Domain Users, Authenticated Users, or Enterprise Domain Controllers. By
default, user accounts and machine accounts are granted the Access this computer from network user
right when computed groups such as Authenticated Users, and for domain controllers, the Enterprise
Domain Controllers group, are defined in the default domain controllers Group Policy Object (GPO).

(C) Microsoft Corporation 2017.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("version_func.inc");
include("host_details.inc");

target_os = policy_microsoft_windows_target_string();
title = "Access this computer from the network";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/User Rights Assignment/" + title;
test_type = "WMI_Query";
select = "AccountList";
keyname = "SeNetworkLogonRight";
wmi_query = "SELECT " + select + " FROM RSOP_UserPrivilegeRight WHERE UserRight = " + keyname;
default = script_get_preference("Value");

if(!policy_verify_win_ver()){
  results = policy_report_wrong_os(target_os:target_os);
}else if(!policy_wmi_access()){
  results = policy_report_no_wmi_access();
}else{
  results = policy_rsop_match(select:select, keyname:keyname, default:default);
}

value = results["value"];
compliant = results["compliant"];
comment = results["comment"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:wmi_query, info:comment);
policy_set_kbs(type:test_type, cmd:wmi_query, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
