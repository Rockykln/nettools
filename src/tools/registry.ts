import type { Tool } from '../core/tool';
import { LANDING_PAGES } from './landing';
import asnLookup from './asn-lookup';
import blacklistCheck from './blacklist-check';
import dnsBenchmark from './dns-benchmark';
import dnsLookup from './dns-lookup';
import dnssecCheck from './dnssec-check';
import domainAvailability from './domain-availability';
import emailHeaders from './email-headers';
import emailSecurity from './email-security';
import httpHeaders from './http-headers';
import ipLookup from './ip-lookup';
import ipRangeToCidr from './ip-range-to-cidr';
import isItDown from './is-it-down';
import macLookup from './mac-lookup';
import portChecker from './port-checker';
import responseTime from './response-time';
import robotsTxt from './robots-txt';
import rootDnsServers from './root-dns-servers';
import socialPreview from './social-preview';
import speedTest from './speed-test';
import sslCheck from './ssl-check';
import subdomainFinder from './subdomain-finder';
import subnetCalculator from './subnet-calculator';
import tcpPing from './tcp-ping';
import ipv6Test from './ipv6-test';
import userAgent from './user-agent';
import whatIsMyIp from './what-is-my-ip';
import whois from './whois';

// To add a tool: create src/tools/<slug>.ts exporting a Tool, then list it here.
export const TOOLS: Tool[] = [
  whatIsMyIp, ipLookup, ipv6Test, userAgent, portChecker, tcpPing, subnetCalculator, ipRangeToCidr, asnLookup, macLookup,
  dnsLookup, dnssecCheck, rootDnsServers,
  whois, domainAvailability, subdomainFinder,
  isItDown, httpHeaders, sslCheck, socialPreview, robotsTxt,
  emailSecurity, blacklistCheck, emailHeaders,
  speedTest, responseTime, dnsBenchmark,
];

/** Landing pages for search terms; routed and in the sitemap, but not listed as separate tools. */
export { LANDING_PAGES };

export const TOOLS_BY_SLUG = new Map([...TOOLS, ...LANDING_PAGES].map((t) => [t.slug, t]));
