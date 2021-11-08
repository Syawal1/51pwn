# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.94210");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.094: Schutz der Webserver-Dateien");
  script_category(ACT_ATTACK); #nb: GSHB_nikto.nasl is in ACT_ATTACK
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04094.html");

  script_tag(name:"summary", value:"IT-Grundschutz M4.094: Schutz der Webserver-Dateien.

  Stand: 14. Ergänzungslieferung (14. EL).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("itg.inc");
include("http_func.inc");
include("port_service_func.inc");

name = 'IT-Grundschutz M4.094: Schutz der Webserver-Dateien\n';
gshbm = "IT-Grundschutz M4.094: ";

port = http_get_port(default:80, ignore_broken:TRUE, ignore_unscanned:TRUE);
host = http_host_name(dont_add_port:TRUE);
brokenwww = http_get_is_marked_broken(port:port, host:host);

nikto = get_kb_item("GSHB/NIKTO");

if(brokenwww){
  result = string("nicht zutreffend");
  desc = string("Es wurde kein Webserver gefunden.");
}else if(nikto == "error"){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.");
}else if(!nikto){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf, es konnte\nvon Nikto kein Ergebniss ermittelt werden.");
}else if(nikto == "none" && !brokenwww){
  result = string("erfüllt");
  desc = string('Nikto konnte keinen in der -Open Source Vulnerability Database- aufgeführten oder durch eine CVE Nummber addressierten Fehler finden.');
}else if(nikto != "none" && !brokenwww){
  result = string("nicht erfüllt");
  desc = string('Nikto hat folgende in der -Open Source Vulnerability Database- aufgeführten oder durch eine CVE Nummber addressierten Fehler gefunden:\n' + nikto);
}

set_kb_item(name:"GSHB/M4_094/result", value:result);
set_kb_item(name:"GSHB/M4_094/desc", value:desc);
set_kb_item(name:"GSHB/M4_094/name", value:name);

silence = get_kb_item("GSHB/silence");
if(!silence)
  itg_send_details(itg_id:'GSHB/M4_094');

exit(0);
