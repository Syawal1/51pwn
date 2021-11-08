# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109995");
  script_version("2019-12-13T11:18:51+0000");
  script_tag(name:"last_modification", value:"2019-12-13 11:18:51 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-09 09:12:10 +0100 (Mon, 09 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.2.A9");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_2_Clients_unter_Windows_8_1.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl",
"Policy/WindowsGeneral/SecurityOptions/win_block_microsoft_accounts.nasl",
"Policy/WindowsGeneral/WindowsComponents/win_ie_defender_smartscreen.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.2 ist der Schutz von Informationen,
die durch und auf Windows 8.1-Clients verarbeiten werden.

Die Standard-Anforderung 'A9: Datenschutz und Datensparsamkeit bei Windows 8.1-Clients' beschreibt,
dass Microsoft-Konten sowie die SmartScreen-Funktion nicht verwendet werden sollten.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");

if (!itg_start_requirement(level:"Standard"))
  exit(0);

title = "Datenschutz und Datensparsamkeit bei Windows 8.1-Clients";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/Accounts: Block Microsoft accounts,
Windows Components/File Explorer/Configure Windows Defender SmartScreen";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109152",
"1.3.6.1.4.1.25623.1.0.109486");

if (host_runs("windows_8.1") != "yes"){
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.2.A9");
  exit(0);
}

results_list = itg_get_policy_control_result(oid_list:oid_list);
result = itg_translate_result(compliant:results_list["compliant"]);
# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);

itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.2.A9");
itg_report(report:report);

exit(0);