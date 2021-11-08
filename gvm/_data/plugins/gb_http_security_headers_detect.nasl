###############################################################################
# OpenVAS Vulnerability Test
#
# HTTP Security Headers Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.112081");
  script_version("2020-10-30T07:53:13+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-10-30 07:53:13 +0000 (Fri, 30 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-10-13 13:12:41 +0200 (Fri, 13 Oct 2017)");
  script_name("HTTP Security Headers Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#div-headers");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"All known security headers are being checked on the host. On completion a report
  will hand back whether a specific security header has been implemented (including its value and if it is deprecated)
  or is missing on the target.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "^HTTP/[12]\.[01] (20[0146]|30[12378])" )
  exit( 0 );

headers_array = make_array();
missing_array = make_array();

known_headers = make_array( "X-Frame-Options", "https://owasp.org/www-project-secure-headers/#x-frame-options",
                            "X-XSS-Protection", "https://owasp.org/www-project-secure-headers/#x-xss-protection, Note: Most major browsers have dropped / deprecated support for this header in 2020.",
                            "X-Content-Type-Options", "https://owasp.org/www-project-secure-headers/#x-content-type-options",
                            "Content-Security-Policy", "https://owasp.org/www-project-secure-headers/#content-security-policy",
                            "X-Permitted-Cross-Domain-Policies", "https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies",
                            "Referrer-Policy", "https://owasp.org/www-project-secure-headers/#referrer-policy",
                            "Feature-Policy", "https://owasp.org/www-project-secure-headers/#feature-policy, Note: The Feature Policy header has been renamed to Permissions Policy",
                            "Permissions-Policy", "https://w3c.github.io/webappsec-feature-policy/#permissions-policy-http-header-field",
                            "Document-Policy", "https://w3c.github.io/webappsec-feature-policy/document-policy#document-policy-http-header" );

# nb: Those are only expected on HTTPS services
if( get_port_transport( port ) > ENCAPS_IP ) {
  known_headers["Strict-Transport-Security"] = "Please check the output of the VTs including 'SSL/TLS:' and 'HSTS' in their name for more information and configuration help.";
  known_headers["Public-Key-Pins"] = "Please check the output of the VTs including 'SSL/TLS:' and 'HPKP' in their name for more information and configuration help. Note: Most major browsers have dropped / deprecated support for this header in 2020.";
  known_headers["Expect-CT"] = "https://owasp.org/www-project-secure-headers/#expect-ct";
}

foreach known_header( keys( known_headers ) ) {
  headergrep = egrep( string:banner, pattern:"^" + known_header + "\s*:.+", icase:TRUE );

  if( headergrep ) {
    found_headers = TRUE;
    header_split = split( headergrep, sep:":", keep:FALSE );
    header_field = chomp( header_split[0] );
    header_value = chomp( header_split[1] );
    header_value = ereg_replace( string:header_value, pattern:"^\s+", replace:"" );
    headers_array[header_field] = header_value;

    set_kb_item( name:tolower( known_header ) + "/available", value:TRUE );
    set_kb_item( name:tolower( known_header ) + "/available/port", value:port );
    set_kb_item( name:tolower( known_header ) + "/" + port + "/banner", value:header_value );

  } else {
    missing_headers = TRUE;
    missing_array[known_header] = known_headers[known_header];
    set_kb_item( name:tolower( known_header ) + "/missing", value:TRUE );
    set_kb_item( name:tolower( known_header ) + "/missing/port", value:port );
  }
}

if( found_headers )
  report += text_format_table( array:headers_array, sep:" | ", columnheader:make_list( "Header Name", "Header Value" ) );

if( missing_headers ) {
  if( found_headers )
    report += '\n\n';
  report += text_format_table( array:missing_array, sep:" | ", columnheader:make_list( "Missing Headers", "More Information" ) );
}

if( strlen( report ) > 0 )
  log_message( port:port, data:report );

exit( 0 );
