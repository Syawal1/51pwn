###############################################################################
# OpenVAS Vulnerability Test
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: Patrik Karlsson
# NASL-Wrapper: autogenerated
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104060");
  script_version("2020-07-07T14:13:50+0000");
  script_tag(name:"last_modification", value:"2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_name("Nmap NSE net: snmp-netstat");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"Attempts to query SNMP for a netstat like output.

SYNTAX:

snmpcommunity:  The community string to use. If not given, it is
''public'', or whatever is passed to 'buildPacket'.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
