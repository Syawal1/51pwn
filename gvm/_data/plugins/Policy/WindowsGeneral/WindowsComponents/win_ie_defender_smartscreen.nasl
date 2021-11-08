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
  script_oid("1.3.6.1.4.1.25623.1.0.109486");
  script_version("2019-12-13T11:11:18+0000");
  script_tag(name:"last_modification", value:"2019-12-13 11:11:18 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"creation_date", value:"2018-06-27 15:29:37 +0200 (Wed, 27 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Windows Defender SmartScreen (Explorer)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"Warn;Block");

  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy allows you to turn Windows Defender SmartScreen on
or off.

SmartScreen helps protect PCs by warning users before running potentially malicious programs
downloaded from the Internet.

This warning is presented as an interstitial dialog shown before running an app that has been
downloaded from the Internet and is unrecognized or known to be malicious.

No dialog is shown for apps that do not appear to be suspicious.

Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.

If you enable this policy, SmartScreen will be turned on for all users.

Its behavior can be controlled by the following options:

  - Warn and prevent bypass

  - Warn

If you enable this policy with the 'Warn and prevent bypass' option, SmartScreen's dialogs will not
present the user with the option to disregard the warning and run the app.

SmartScreen will continue to show the warning on subsequent attempts to run the app.

If you enable this policy with the 'Warn' option, SmartScreen's dialogs will warn the user that the
app appears suspicious, but will permit the user to disregard the warning and run the app anyway.

SmartScreen will not warn the user again for that app if the user tells SmartScreen to run the app.

If you disable this policy, SmartScreen will be turned off for all users.

Users will not be warned if they try to run suspicious apps from the Internet.

If you do not configure this policy, SmartScreen will be enabled by default, but users may change
their settings.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Configure Windows Defender SmartScreen";
solution = "Set following UI path accordingly:
Windows Components/File Explorer/" + title;
type = "HKLM";
key = "Software\Policies\Microsoft\Windows\System";
item = "ShellSmartScreenLevel";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_reg_sz(key:key, item:item, type:type, default:default, partial:FALSE);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
