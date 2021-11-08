###############################################################################
# OpenVAS Vulnerability Test
#
# SurgeMail Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900839");
  script_version("2020-08-25T06:34:32+0000");
  script_tag(name:"last_modification", value:"2020-08-25 06:34:32 +0000 (Tue, 25 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SurgeMail Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "smtpserver_detect.nasl", "imap4_banner.nasl", "popserver_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 7110, 7026, "Services/smtp", 25, 465, 587, "Services/imap", 143, "Services/pop3", 110, 995);

  script_tag(name:"summary", value:"This script detects the installed version of SurgeMail
  and sets the result into the knowledgebase.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("smtp_func.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("misc_func.inc");

port = 7110;

banner = http_get_remote_headers(port:port);

if("surgemail" >< banner){
  set_kb_item(name:"SurgeMail/Installed", value:TRUE);

  version = "unknown";
  ver = eregmatch(pattern:"Version ([0-9.]+)([a-z][0-9]?(-[0-9])?)?", string:banner);

  if(ver[1]){
    if(!isnull(ver[2]))
      version = ver[1] + "." + ver[2];
    else
      version = ver[1];

    version = ereg_replace(pattern:"-", replace:".", string:version);

    set_kb_item(name:"SurgeMail/Ver", value:version);
  }

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:netwin:surgemail:");
  if (!cpe)
    cpe = "cpe:/a:netwin:surgemail";

  register_product(cpe:cpe, location:"/", port:port, service:"smtp");

  log_message(data:build_detection_report(app:"Netwin Surgemail",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:ver[0]),
                                          port:port);
  exit(0);
}

surgemail_port = http_get_port(default:7026);

rcvRes = http_get_cache(item:"/", port:surgemail_port);

if(egrep(pattern:"SurgeMail", string:rcvRes, icase:1)){
  set_kb_item(name:"SurgeMail/Installed", value:TRUE);

  smtpPorts = smtp_get_ports();

  foreach port(smtpPorts){
    banner = smtp_get_banner(port:port);
    if("surgemail" >< banner){
      ver = eregmatch(pattern:"Version ([0-9.]+)([a-z][0-9]?(-[0-9])?)?", string:banner);
      version = "unknown";

      if(ver[1]){
        if(!isnull(ver[2]))
          version = ver[1] + "." + ver[2];
        else
          version = ver[1];

        version = ereg_replace(pattern:"-", replace:".", string:version);

        set_kb_item(name:"SurgeMail/Ver", value:version);
      }

      cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:netwin:surgemail:");
      if (!cpe)
      cpe = "cpe:/a:netwin:surgemail";

      register_product(cpe:cpe, location:"/", port:port, service:"smtp");

      log_message(data:build_detection_report(app:"Netwin Surgemail",
                                              version:version,
                                              install:"/",
                                              cpe:cpe,
                                              concluded:ver[0]),
                                              port:port);
    }
  }

  imapPorts = imap_get_ports();
  foreach port(imapPorts){
    banner = imap_get_banner(port:port);
    if("surgemail" >< banner){
      ver = eregmatch(pattern:"Version ([0-9.]+)([a-z][0-9]?(-[0-9])?)?", string:banner);
      version = "unknown";

      if(ver[1]){
        if(!isnull(ver[2]))
          version = ver[1] + "." + ver[2];
        else
          version = ver[1];

        version = ereg_replace(pattern:"-", replace:".", string:version);

        set_kb_item(name:"SurgeMail/Ver", value:version);
      }

      cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:netwin:surgemail:");
      if (!cpe)
      cpe = "cpe:/a:netwin:surgemail";

      register_product(cpe:cpe, location:"/", port:port, service:"imap");

      log_message(data:build_detection_report(app:"Netwin Surgemail",
                                              version:version,
                                              install:"/",
                                              cpe:cpe,
                                              concluded:ver[0]),
                                              port:port);
    }
  }

  popPorts = pop3_get_ports();
  foreach port(popPorts){
    banner = pop3_get_banner(port:port);
    if("surgemail" >< banner){
      ver = eregmatch(pattern:"Version ([0-9.]+)([a-z][0-9]?(-[0-9])?)?", string:banner);
      version = "unknown";

      if(ver[1]){
        if(!isnull(ver[2]))
          version = ver[1] + "." + ver[2];
        else
          version = ver[1];

        version = ereg_replace(pattern:"-", replace:".", string:version);

        set_kb_item(name:"SurgeMail/Ver", value:version);
      }

      cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:netwin:surgemail:");
      if (!cpe)
      cpe = "cpe:/a:netwin:surgemail";

      register_product(cpe:cpe, location:"/", port:port, service:"pop3");

      log_message(data:build_detection_report(app:"Netwin Surgemail",
                                              version:version,
                                              install:"/",
                                              cpe:cpe,
                                              concluded:ver[0]),
                                              port:port);
    }
  }
}

exit(0);
