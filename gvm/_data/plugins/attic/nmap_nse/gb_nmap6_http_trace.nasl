###############################################################################
# OpenVAS Vulnerability Test
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: Paulino Calderon
# NASL-Wrapper: autogenerated
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803556");
  script_version("2020-07-07T14:13:50+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)");
  script_tag(name:"creation_date", value:"2013-02-28 19:00:45 +0530 (Thu, 28 Feb 2013)");
  script_name("Nmap NSE 6.01: http-trace");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");

  script_tag(name:"summary", value:"Sends an HTTP TRACE request and shows if the method TRACE is enabled. If debug is enabled, it
returns the header fields that were modified in the response.

SYNTAX:

http-trace.path:  Path to URI

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

http-max-cache-size:  The maximum memory size (in bytes) of the cache.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
