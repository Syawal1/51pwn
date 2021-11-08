###############################################################################
# OpenVAS Vulnerability Test
#
# List errors from Policy for BSI-TR-03116-4 Test
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.96177");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-02-27T07:29:29+0000");
  script_tag(name:"last_modification", value:"2020-02-27 07:29:29 +0000 (Thu, 27 Feb 2020)");
  script_tag(name:"creation_date", value:"2016-03-07 09:09:05 +0100 (Mon, 07 Mar 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BSI-TR-03116-4: Errors");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Policy");

  script_tag(name:"summary", value:"List errors from Policy for BSI-TR-03116-4 Test.

  This NVT has been deprecated as is not needed anymore.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
