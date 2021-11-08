###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Informix Dynamic Server Version Detection (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.902547");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-03-27T14:05:33+0000");
  script_tag(name:"last_modification", value:"2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IBM Informix Dynamic Server Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the installed IBM Informix Dynamic Server version.");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"oninit", sock:sock);
foreach bin(paths) {

  bin = chomp(bin);
  if(!bin)
    continue;

  version = ssh_get_bin_version(full_prog_name:bin, sock:sock, version_argv:"-V", ver_pattern:"IBM Informix Dynamic Server Version ([0-9.]+)");

  if(!isnull(version[1])) {

    set_kb_item(name:"IBM/Informix/Dynamic/Server/Lin/Ver", value:version[1]);

    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:ibm:informix_dynamic_server:");
    if(!cpe)
      cpe = "cpe:/a:ibm:informix_dynamic_server";

    register_product(cpe:cpe, location:bin, service:"ssh-login");
    log_message(data:build_detection_report(app:"IBM Informix Dynamic Server",
                                            version:version[1],
                                            install:bin,
                                            cpe:cpe,
                                            concluded:version[0]));
  }
}

ssh_close_connection();
exit(0);
