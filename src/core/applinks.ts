/** Apple App Site Association: links to these pages open the nettools iPhone app when it is installed. */
export const APP_ID = 'S8KC2H969N.com.rockykln.nettools';

// Pages with a native screen in the app, plus the aliases that redirect to them.
export const APP_LINK_PATHS = [
  '/what-is-my-ip', '/ipv6-test', '/speed-test', '/dns-lookup', '/dns-benchmark', '/dnssec-check', '/root-dns-servers',
  '/port-checker', '/tcp-ping', '/subnet-calculator', '/ip-range-to-cidr', '/mac-lookup', '/ip-lookup', '/asn-lookup',
  '/whois', '/domain-availability', '/subdomain-finder', '/is-it-down', '/response-time', '/http-headers', '/ssl-check',
  '/social-preview', '/robots-txt', '/email-security', '/blacklist-check', '/email-headers',
  '/my-ip', '/whats-my-ip', '/ip-address', '/myip', '/whatsmyip', '/cidr-calculator', '/ip-calculator', '/speedtest',
  '/dns', '/rdap', '/open-port-checker', '/ping', '/mac-address-lookup', '/spam-blacklist-check', '/dnsbl',
];

export function appSiteAssociation(): unknown {
  return {
    applinks: {
      apps: [],
      details: [{ appIDs: [APP_ID], components: APP_LINK_PATHS.map((path) => ({ '/': path })) }],
    },
  };
}
