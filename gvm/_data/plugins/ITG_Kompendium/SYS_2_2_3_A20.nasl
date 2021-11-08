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
  script_oid("1.3.6.1.4.1.25623.1.0.109982");
  script_version("2019-12-13T11:18:51+0000");
  script_tag(name:"last_modification", value:"2019-12-13 11:18:51 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-18 13:20:09 +0100 (Mon, 18 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.3.A20");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl",
"Policy/WindowsGeneral/UserAccountControl/win_uac_admin_approval_mode.nasl",
"Policy/WindowsGeneral/UserAccountControl/win_uac_uiaccess_apps.nasl",
"Policy/WindowsGeneral/UserAccountControl/win_uac_behaviour_elevation_prompt_admin.nasl",
"Policy/WindowsGeneral/UserAccountControl/win_uac_behavior_elevation_prompt_users.nasl",
"Policy/WindowsGeneral/UserAccountControl/win_uac_apps_install_prompt.nasl",
"Policy/WindowsGeneral/UserAccountControl/win_uac_elevate_apps_sec_locations.nasl",
"Policy/WindowsGeneral/UserAccountControl/win_uac_all_admins_approval_mode.nasl",
"Policy/WindowsGeneral/UserAccountControl/win_uac_sec_desktop_when_prompt.nasl",
"Policy/WindowsGeneral/UserAccountControl/win_uac_virtualize_file_reg_fail.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Standard-Anforderung 'A20: Einsatz der Benutzerkontensteuerung fuer privilegierte Konten' beschreibt,
dass die Konfigurationsparameter der UAC zwischen Bedienbarkeit und Sicherheitsniveau abgewogen sein
sollten.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");

if (!itg_start_requirement(level:"Standard"))
  exit(0);

title = "Einsatz der Benutzerkontensteuerung fuer privilegierte Konten";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Admin Approval Mode for the Built-in Administrator account,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for standard users,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Detect application installations and prompt for elevation,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Only elevate UIAccess applications that are installed in secure locations,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Run all administrators in Admin Approval Mode,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Switch to the secure desktop when prompting for elevation,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Virtualize file and registry write failures to per-user locations";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109241",
"1.3.6.1.4.1.25623.1.0.109242",
"1.3.6.1.4.1.25623.1.0.109243",
"1.3.6.1.4.1.25623.1.0.109244",
"1.3.6.1.4.1.25623.1.0.109245",
"1.3.6.1.4.1.25623.1.0.109246",
"1.3.6.1.4.1.25623.1.0.109247",
"1.3.6.1.4.1.25623.1.0.109248",
"1.3.6.1.4.1.25623.1.0.109249");

if (!policy_host_runs_windows_10()) {
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A20");
  exit(0);
}

results_list = itg_get_policy_control_result(oid_list:oid_list);
result = itg_translate_result(compliant:results_list["compliant"]);
# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);

itg_report(report:report);
itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A20");

exit(0);