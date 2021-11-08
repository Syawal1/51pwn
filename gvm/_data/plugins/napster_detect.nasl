###############################################################################
# OpenVAS Vulnerability Test
#
# Detect the presence of Napster
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2005 by Noam Rathaus <noamr@securiteam.com>, Beyond Security Ltd.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10344");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Detect the presence of Napster");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Beyond Security");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/napster", 6699);

  script_tag(name:"summary", value:"Napster is running on a remote computer.

  Napster is used to share MP3 across the network, and can be misused (by modifying the three first bytes
  of a target file) to transfer any file off a remote site.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

uk = 0;
port = service_get_port(proto:"napster", default:1);
if(port==1){
  port = 6699;
  uk = 1;
}

if(!get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if(!soc) exit(0);

res = recv(socket:soc, length:50);
if("1" >< res){

  data = string("GET\r\n");
  send(socket:soc, data:data);
  res = recv(socket:soc, length:50);
  if(!res){

    data = string("GET /\r\n");
    send(socket:soc, data:data);
    res = recv(socket:soc, length:150);

    if("FILE NOT SHARED" >< res){
      report = "Napster was detected on the target system.";
      log_message(data:report, port:port);
      if(uk)service_register(proto:"napster", port:port);
    }
  }
}

close(soc);
