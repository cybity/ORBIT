import { getJson, githubHeaders, HttpError, errorMessage } from "./api.js";
import { md5 } from "./md5.js";

export const TOOL_VERSION = "0.1.0";

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const DNS_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "CNAME", "CAA", "SOA"];
const DNS_TYPE_CODES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  CAA: 257,
};

const MULTI_LABEL_SUFFIXES = new Set([
  "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "nhs.uk", "org.uk", "plc.uk",
  "com.au", "edu.au", "gov.au", "net.au", "org.au",
  "co.jp", "ne.jp", "or.jp",
  "co.nz", "net.nz", "org.nz",
  "com.br", "net.br", "org.br",
  "com.cn", "net.cn", "org.cn",
  "com.hk", "com.sg", "com.tw", "com.my", "com.ph", "com.vn", "com.pk",
  "co.in", "co.za", "co.kr", "co.id", "co.il", "co.ke",
  "com.ar", "com.mx", "com.tr", "com.ua", "com.pl", "com.ng", "com.sa", "com.eg",
  "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app", "herokuapp.com",
  "blogspot.com", "wordpress.com", "tumblr.com", "neocities.org", "web.app",
  "firebaseapp.com", "azurewebsites.net", "cloudfront.net", "onrender.com", "fly.dev",
  "railway.app", "surge.sh", "readthedocs.io", "notion.site", "wixsite.com", "weebly.com",
  "amazonaws.com",
]);

const RISKY_PORTS = new Map([
  [21, "FTP"],
  [22, "SSH"],
  [23, "Telnet"],
  [25, "SMTP"],
  [445, "SMB"],
  [1433, "MSSQL"],
  [2375, "Docker"],
  [3306, "MySQL"],
  [3389, "RDP"],
  [5432, "PostgreSQL"],
  [5900, "VNC"],
  [6379, "Redis"],
  [9200, "Elasticsearch"],
  [11211, "Memcached"],
  [27017, "MongoDB"],
]);

const SHORTENERS = new Set([
  "bit.ly", "buff.ly", "cutt.ly", "goo.gl", "is.gd", "ow.ly", "rebrand.ly",
  "s.id", "shorturl.at", "t.co", "tiny.cc", "tinyurl.com", "trib.al",
]);

const INTERESTING_SUBDOMAINS = /(^|\.)(admin|administrator|auth|backup|ci|dashboard|db|dev|ftp|git|gitlab|internal|intranet|jira|jenkins|mail|portal|qa|s3|sso|stage|staging|test|vpn)\./i;

const TYPE_LABELS = {
  domain: "DOMAIN",
  ip: "IP",
  username: "HANDLE",
  email: "EMAIL",
  url: "URL",
};

export function typeLabel(type) {
  return TYPE_LABELS[type] || "TARGET";
}

function isIPv4(value) {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  );
}

function isIPv6(value) {
  const candidate = value.replace(/^\[|\]$/g, "");
  return (
    candidate.includes(":") &&
    /^[0-9a-f:]+$/i.test(candidate) &&
    (candidate.match(/::/g) || []).length <= 1
  );
}

export function isIp(value) {
  return isIPv4(value) || isIPv6(value);
}

function isDomain(value) {
  const host = value.toLowerCase().replace(/\.$/, "");
  if (host.length === 0 || host.length > 253) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i.test(labels[labels.length - 1])) return false;
  return labels.every((label) =>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)
  );
}

function toAsciiHost(value) {
  try {
    return new URL(`http://${value}`).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return value.toLowerCase().replace(/\.$/, "");
  }
}

export function detectType(value) {
  const raw = String(value || "").trim();
  if (!raw) return "unknown";

  if (/^https?:\/\//i.test(raw)) return "url";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(raw)) return "email";

  const ipCandidate = raw.replace(/^\[|\]$/g, "");
  if (isIp(ipCandidate)) return "ip";

  if (raw.startsWith("@")) return "username";
  if (/^[^\s/?#]+\.[^\s/?#]+(?:[/?#]|:\d+)/.test(raw)) return "url";
  if (isDomain(toAsciiHost(raw))) return "domain";
  if (/^[a-z0-9][a-z0-9_.-]{0,38}$/i.test(raw)) return "username";

  return "unknown";
}

export function normalizeTarget(value, requestedType = "auto") {
  const raw = String(value || "").trim();
  if (!raw) throw new Error("Enter a target first.");

  const type = requestedType && requestedType !== "auto" ? requestedType : detectType(raw);

  if (type === "url") {
    let parsed;
    try {
      const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
      parsed = new URL(hasScheme ? raw : `https://${raw}`);
    } catch {
      throw new Error("That URL is not valid. Use a full URL or host/path.");
    }
    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error("Only HTTP and HTTPS URLs are supported.");
    }
    parsed.username = "";
    parsed.password = "";
    return parsed.href;
  }

  if (type === "email") {
    const email = raw.replace(/^mailto:/i, "").trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email)) {
      throw new Error("That email address is not valid.");
    }
    return email;
  }

  if (type === "ip") {
    const ip = raw.replace(/^\[|\]$/g, "").toLowerCase();
    if (!isIp(ip)) throw new Error("That IP address is not valid.");
    return ip;
  }

  if (type === "username") {
    const username = raw.replace(/^@/, "").trim();
    if (!/^[a-z0-9][a-z0-9_.-]{0,38}$/i.test(username)) {
      throw new Error("Handles must be 1–39 letters, numbers, dots, hyphens, or underscores.");
    }
    return username;
  }

  if (type === "domain") {
    let candidate = raw;
    if (/^https?:\/\//i.test(candidate)) {
      try {
        candidate = new URL(candidate).hostname;
      } catch {
        throw new Error("That domain is not valid.");
      }
    }
    candidate = candidate
      .replace(/^\/+|\/+$/g, "")
      .split("/")[0]
      .split("?")[0]
      .split("#")[0]
      .replace(/:\d+$/, "");
    candidate = toAsciiHost(candidate);
    if (!isDomain(candidate)) throw new Error("That domain is not valid.");
    return candidate;
  }

  throw new Error("Could not identify that target. Use a domain, IP, @handle, email, or URL.");
}

export function rootDomain(host) {
  if (isIp(host)) return host;
  const labels = host.toLowerCase().split(".");
  if (labels.length <= 2) return labels.join(".");

  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join(".");
  }

  return lastTwo;
}

function stripQuotes(value) {
  if (typeof value !== "string") return String(value);
  return value.replace(/^"|"$/g, "").replace(/"\s+"/g, "");
}

async function dnsQuery(name, type, timeout = 10000) {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const data = await getJson(url, {
    headers: { Accept: "application/dns-json" },
    timeout,
  });

  const code = DNS_TYPE_CODES[type];
  const answers = Array.isArray(data.Answer) ? data.Answer : [];
  const values = answers
    .filter((answer) => answer.type === code)
    .map((answer) => stripQuotes(answer.data));

  return {
    values: [...new Set(values)],
    status: data.Status,
    truncated: Boolean(data.TC),
  };
}

async function lookupDns(name) {
  const records = {};

  await Promise.all(
    DNS_TYPES.map(async (type) => {
      try {
        records[type] = await dnsQuery(name, type);
      } catch (error) {
        records[type] = {
          values: [],
          status: null,
          truncated: false,
          error: errorMessage(error),
        };
      }
    })
  );

  return records;
}

let dnsBootstrapPromise = null;
let ipv4BootstrapPromise = null;
let ipv6BootstrapPromise = null;

async function getBootstrap(name) {
  try {
    const data = await getJson(`https://data.iana.org/rdap/${name}.json`, {
      timeout: 10000,
    });
    return data && Array.isArray(data.services) ? data.services : [];
  } catch {
    return [];
  }
}

function pickHttpsBase(urls) {
  if (!Array.isArray(urls)) return null;
  return urls.find((url) => typeof url === "string" && url.startsWith("https://")) || null;
}

async function directDomainRdapUrl(domain) {
  if (!dnsBootstrapPromise) dnsBootstrapPromise = getBootstrap("dns");
  const services = await dnsBootstrapPromise;
  let best = null;

  for (const [tlds, urls] of services) {
    const base = pickHttpsBase(urls);
    if (!base || !Array.isArray(tlds)) continue;

    for (const tld of tlds) {
      const suffix = String(tld).toLowerCase();
      if (domain === suffix || domain.endsWith(`.${suffix}`)) {
        if (!best || suffix.length > best.suffix.length) {
          best = { suffix, base };
        }
      }
    }
  }

  if (!best) return null;
  const base = best.base.endsWith("/") ? best.base : `${best.base}/`;
  return `${base}domain/${encodeURIComponent(domain)}`;
}

function ipv4ToInt(ip) {
  return ip.split(".").reduce((acc, part) => ((acc << 8) | Number(part)) >>> 0, 0);
}

function ipv4InCidr(ip, cidr) {
  const [network, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(network) & mask);
}

function ipv6ToBigInt(ip) {
  return BigInt(`0x${expandIpv6(ip).replace(/:/g, "")}`);
}

function ipv6InCidr(ip, cidr) {
  const [network, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  const hostBits = BigInt(128 - prefix);
  const mask = ((1n << 128n) - 1n) ^ ((1n << hostBits) - 1n);
  return (ipv6ToBigInt(ip) & mask) === (ipv6ToBigInt(network) & mask);
}

async function directIpRdapUrl(ip) {
  const isV4 = isIPv4(ip);

  if (isV4) {
    if (!ipv4BootstrapPromise) ipv4BootstrapPromise = getBootstrap("ipv4");
  } else if (!ipv6BootstrapPromise) {
    ipv6BootstrapPromise = getBootstrap("ipv6");
  }

  const services = isV4 ? await ipv4BootstrapPromise : await ipv6BootstrapPromise;
  let best = null;

  for (const [cidrs, urls] of services) {
    const base = pickHttpsBase(urls);
    if (!base || !Array.isArray(cidrs)) continue;

    for (const cidr of cidrs) {
      const prefix = Number(String(cidr).split("/")[1]);
      const matches = isV4 ? ipv4InCidr(ip, cidr) : ipv6InCidr(ip, cidr);
      if (matches && (!best || prefix > best.prefix)) {
        best = { prefix, base };
      }
    }
  }

  if (!best) return null;
  const base = best.base.endsWith("/") ? best.base : `${best.base}/`;
  return `${base}ip/${encodeURIComponent(ip)}`;
}

async function rdapLookup(kind, value) {
  const unified = `https://rdap.org/${kind}/${encodeURIComponent(value)}`;

  try {
    return await getJson(unified, { timeout: 20000 });
  } catch (primaryError) {
    let direct = null;

    try {
      direct =
        kind === "domain"
          ? await directDomainRdapUrl(value)
          : await directIpRdapUrl(value);
    } catch {
      direct = null;
    }

    if (!direct) throw primaryError;

    try {
      return await getJson(direct, { timeout: 20000 });
    } catch (fallbackError) {
      throw new Error(
        `${errorMessage(primaryError)}; direct registry: ${errorMessage(fallbackError)}`
      );
    }
  }
}

async function reverseDns(ip) {
  let pointer;

  if (isIPv4(ip)) {
    pointer = `${ip.split(".").reverse().join(".")}.in-addr.arpa`;
  } else {
    const expanded = expandIpv6(ip);
    pointer = `${expanded.replace(/:/g, "").split("").reverse().join(".")}.ip6.arpa`;
  }

  return dnsQuery(pointer, "PTR");
}

function expandIpv6(ip) {
  const [head, tail] = ip.toLowerCase().split("::");
  const headParts = head ? head.split(":") : [];
  const tailParts = tail ? tail.split(":") : [];
  const missing = Math.max(0, 8 - headParts.length - tailParts.length);
  return [...headParts, ...Array(missing).fill("0"), ...tailParts]
    .map((part) => part.padStart(4, "0"))
    .join(":");
}

function dateOnly(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toISOString().slice(0, 10);
}

function waybackDate(value) {
  const raw = String(value || "");
  if (/^\d{14}$/.test(raw)) {
    return `${raw.slice(0, 4)}-${raw.slice(4, 6)}-${raw.slice(6, 8)}`;
  }
  return dateOnly(value);
}

function ageInDays(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return Math.floor((Date.now() - date.getTime()) / 86400000);
}

function compactNumber(value) {
  return Number(value || 0).toLocaleString("en-US");
}

function vcardValue(entity, key) {
  const fields = entity && entity.vcardArray && entity.vcardArray[1];
  if (!Array.isArray(fields)) return null;
  const field = fields.find((row) => Array.isArray(row) && row[0] === key);
  return field && field[3] ? field[3] : null;
}

function eventMap(events) {
  const out = {};
  if (!Array.isArray(events)) return out;
  for (const event of events) {
    if (event && event.eventAction) {
      out[event.eventAction] = event.eventDate || null;
    }
  }
  return out;
}

function buildDnsFinding(host, records) {
  const counts = {};
  const failures = [];

  for (const [type, result] of Object.entries(records)) {
    counts[type] = result.values.length;
    if (result.error) failures.push(`${type}: ${result.error}`);
  }

  const summaryParts = Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([type, count]) => `${type} ${count}`);
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);

  return {
    kind: "dns",
    status: total > 0 ? "ok" : "empty",
    severity: "info",
    summary:
      total > 0
        ? `${summaryParts.join(" · ")}${failures.length ? ` · ${failures.length} query failures` : ""}`
        : `No DNS records returned${failures.length ? `; ${failures.length} queries failed` : ""}.`,
    data: { hostname: host, records },
    raw: records,
    wide: true,
  };
}

function parseRdapDomain(raw, query) {
  const events = eventMap(raw.events);
  const registrarEntity = (raw.entities || []).find(
    (entity) => Array.isArray(entity.roles) && entity.roles.includes("registrar")
  );
  const registrar = vcardValue(registrarEntity, "fn");
  const registrarId =
    registrarEntity &&
    Array.isArray(registrarEntity.publicIds) &&
    registrarEntity.publicIds.find((item) => /IANA/i.test(item.type || ""))
      ? registrarEntity.publicIds.find((item) => /IANA/i.test(item.type || "")).identifier
      : null;

  const nameservers = (raw.nameservers || [])
    .map((server) => server.ldhName)
    .filter(Boolean);

  return {
    kind: "rdap-domain",
    status: "ok",
    severity: "info",
    summary: [
      registrar || "Registrar not listed",
      events.registration ? `registered ${dateOnly(events.registration)}` : null,
      events.expiration ? `expires ${dateOnly(events.expiration)}` : null,
    ]
      .filter(Boolean)
      .join(" · "),
    data: {
      query,
      handle: raw.handle || null,
      status: Array.isArray(raw.status) ? raw.status : [],
      registrar,
      registrarId,
      registered: events.registration || null,
      updated: events["last changed"] || null,
      expires: events.expiration || null,
      nameservers,
      dnssec: Boolean(raw.secureDNS && raw.secureDNS.delegationSigned),
      entityCount: Array.isArray(raw.entities) ? raw.entities.length : 0,
      rdapUrl: `https://rdap.org/domain/${encodeURIComponent(query)}`,
    },
    raw,
    signals: (() => {
      const age = ageInDays(events.registration);
      if (age !== null && age <= 30) {
        return [{
          severity: "attention",
          title: "Recently registered domain",
          detail: `Registration date is ${dateOnly(events.registration)} (${age} days ago). Verify ownership before trusting it.`,
        }];
      }
      return [];
    })(),
  };
}

async function crtShCertificates(root) {
  const query = encodeURIComponent(`%.${root}`);
  const url = `https://crt.sh/?q=${query}&output=json&exclude=expired&deduplicate=Y`;
  let raw;

  try {
    raw = await getJson(url, { timeout: 30000 });
  } catch (error) {
    if (error instanceof HttpError && [404, 502, 503].includes(error.status)) {
      raw = await getJson(`https://crt.sh/?q=${query}&output=json`, { timeout: 30000 });
    } else {
      throw error;
    }
  }

  if (!Array.isArray(raw)) {
    throw new Error("crt.sh returned an unexpected response.");
  }

  return raw;
}

async function certSpotterCertificates(root) {
  const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(root)}&include_subdomains=true&expand=dns_names`;
  const raw = await getJson(url, { timeout: 20000 });

  if (!Array.isArray(raw)) {
    throw new Error("CertSpotter returned an unexpected response.");
  }

  return raw.map((item) => {
    const names = Array.isArray(item.dns_names) ? item.dns_names : [];
    const issuer = item.issuer || {};
    return {
      id: item.id,
      common_name: names[0] || root,
      name_value: names.length ? names.join("\n") : root,
      not_before: item.not_before || null,
      not_after: item.not_after || null,
      issuer_name: issuer.name || issuer.friendly_name || issuer.ca_domain || "Unknown issuer",
    };
  });
}

async function certificateLookup(root) {
  let raw;
  let provider = "crt.sh";
  let sourceUrl = `https://crt.sh/?q=${encodeURIComponent(`%.${root}`)}`;

  try {
    raw = await crtShCertificates(root);
  } catch (primaryError) {
    try {
      raw = await certSpotterCertificates(root);
      provider = "CertSpotter";
      sourceUrl = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(root)}&include_subdomains=true&expand=dns_names`;
    } catch (fallbackError) {
      throw new Error(
        `Certificate transparency failed at crt.sh (${errorMessage(primaryError)}) and CertSpotter (${errorMessage(fallbackError)}).`
      );
    }
  }

  const names = new Set();
  const issuers = new Map();
  let latestExpiry = null;
  let earliestIssue = null;

  for (const certificate of raw) {
    if (!certificate || typeof certificate.name_value !== "string") continue;

    for (const rawName of certificate.name_value.split("\n")) {
      const name = rawName.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
      if (!name || name.startsWith("*.")) continue;
      if (name === root || name.endsWith(`.${root}`)) {
        names.add(name);
        if (names.size >= 2000) break;
      }
    }

    const issuer = certificate.issuer_name || "Unknown issuer";
    issuers.set(issuer, (issuers.get(issuer) || 0) + 1);

    if (certificate.not_after && (!latestExpiry || certificate.not_after > latestExpiry)) {
      latestExpiry = certificate.not_after;
    }

    if (certificate.not_before && (!earliestIssue || certificate.not_before < earliestIssue)) {
      earliestIssue = certificate.not_before;
    }
  }

  const sortedNames = [...names].sort();
  const subdomains = sortedNames.filter((name) => name !== root);
  const interesting = subdomains.filter((name) => INTERESTING_SUBDOMAINS.test(name));
  const topIssuers = [...issuers.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  return {
    kind: "certs",
    source: provider,
    sourceUrl,
    status: raw.length > 0 ? "ok" : "empty",
    severity: interesting.length ? "note" : "info",
    summary:
      raw.length > 0
        ? `${compactNumber(raw.length)} certs · ${compactNumber(subdomains.length)} subdomains`
        : "No certificates returned.",
    data: {
      query: root,
      provider,
      certificateCount: raw.length,
      uniqueNames: sortedNames.length,
      subdomains,
      interestingSubdomains: interesting,
      issuers: topIssuers,
      earliestIssue,
      latestExpiry,
      truncated: names.size >= 2000,
      sourceUrl,
    },
    raw: null,
    wide: true,
    signals: interesting.length
      ? [{
          severity: "note",
          title: "Potentially sensitive hostnames in CT logs",
          detail: `${interesting.length} hostname${interesting.length === 1 ? "" : "s"} match common admin, dev, VPN, or internal naming patterns: ${interesting.slice(0, 6).join(", ")}${interesting.length > 6 ? "…" : ""}`,
        }]
      : [],
  };
}

function parseMailPosture(domain, records) {
  const mx = records.MX.values;
  const txt = records.TXT.values;
  const dmarcRecords = records.DMARC ? records.DMARC.values : [];

  const spf = txt.find((value) => /^v=spf1\b/i.test(value.trim())) || null;
  const dmarc = dmarcRecords.find((value) => /^v=dmarc1\b/i.test(value.trim())) || null;
  const nullMx = mx.some((value) => /(^|\s)\.\s*$/.test(value.trim()));
  const spfAll = spf ? (spf.match(/\b([+~?-]?)all\b/i) || [])[0] || null : null;
  const dmarcPolicy = dmarc ? ((dmarc.match(/\bp=([a-z]+)/i) || [])[1] || null) : null;

  return { domain, mx, spf, spfAll, dmarc, dmarcPolicy, nullMx };
}

function buildMailFinding(posture) {
  const { domain, mx, spf, spfAll, dmarc, dmarcPolicy, nullMx } = posture;
  const parts = [
    nullMx ? "null MX" : `MX ${mx.length}`,
    spf ? "SPF found" : "no SPF",
    dmarc ? `DMARC ${dmarcPolicy || "found"}` : "no DMARC",
  ];

  const signals = [];

  if (!nullMx) {
    if (!spf) {
      signals.push({
        severity: "note",
        title: "No SPF record advertised",
        detail: `${domain} does not publish an SPF policy. This is a mail-authentication gap, not proof of exploitability.`,
      });
    }

    if (!dmarc) {
      signals.push({
        severity: "note",
        title: "No DMARC policy advertised",
        detail: `${domain} does not publish a DMARC record at _dmarc.${domain}.`,
      });
    }

    if (spfAll && spfAll.startsWith("+")) {
      signals.push({
        severity: "attention",
        title: "Permissive SPF policy",
        detail: `SPF ends with ${spfAll}, which authorizes all sending hosts. This can enable direct email spoofing.`,
      });
    }

    if (dmarcPolicy === "none") {
      signals.push({
        severity: "note",
        title: "DMARC is monitor-only",
        detail: "DMARC policy is p=none. Reports are collected, but failing mail is not quarantined or rejected.",
      });
    }
  }

  return {
    kind: "mail",
    status: mx.length || nullMx ? "ok" : "empty",
    severity: signals.some((signal) => signal.severity === "attention")
      ? "attention"
      : signals.length
        ? "note"
        : "info",
    summary: `${parts.join(" · ")}${nullMx ? " · domain does not accept mail" : ""}`,
    data: posture,
    raw: posture,
    signals,
  };
}

async function mailPosture(domain) {
  const [mx, txt, dmarc] = await Promise.all([
    dnsQuery(domain, "MX"),
    dnsQuery(domain, "TXT"),
    dnsQuery(`_dmarc.${domain}`, "TXT"),
  ]);

  return parseMailPosture(domain, { MX: mx, TXT: txt, DMARC: dmarc });
}

async function ipwho(ip) {
  try {
    const data = await getJson(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      timeout: 12000,
    });
    if (!data || data.success === false) return { data: null, error: null };
    return { data, error: null };
  } catch (error) {
    return { data: null, error: errorMessage(error) };
  }
}

async function shodanInternetDb(ip) {
  try {
    const data = await getJson(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
      timeout: 15000,
    });
    return { data, error: null };
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) {
      return { data: null, error: null };
    }
    return { data: null, error: errorMessage(error) };
  }
}

function exposureSignals(hosts) {
  const signals = [];

  for (const host of hosts) {
    const exposure = host.shodan;

    if (!exposure) continue;

    if (Array.isArray(exposure.vulns) && exposure.vulns.length) {
      signals.push({
        severity: "attention",
        title: `Known vulnerabilities observed on ${host.ip}`,
        detail: `${exposure.vulns.length} CVE${exposure.vulns.length === 1 ? "" : "s"} associated with exposed services: ${exposure.vulns.slice(0, 5).join(", ")}${exposure.vulns.length > 5 ? "…" : ""}`,
      });
    }

    const risky = (exposure.ports || [])
      .map((port) => ({ port, label: RISKY_PORTS.get(port) }))
      .filter((entry) => entry.label);

    if (risky.length) {
      signals.push({
        severity: "note",
        title: `Remote-access or data service observed on ${host.ip}`,
        detail: risky.map((entry) => `${entry.port}/${entry.label}`).join(", "),
      });
    }

    if (Array.isArray(exposure.tags) && exposure.tags.some((tag) => /compromised|malware|botnet/i.test(tag))) {
      signals.push({
        severity: "attention",
        title: `Adverse tag on ${host.ip}`,
        detail: `Shodan InternetDB tags: ${exposure.tags.join(", ")}`,
      });
    }
  }

  return signals;
}

async function buildNetworkFinding(ips, { ptr = false } = {}) {
  const unique = [...new Set(ips)].slice(0, 4);

  if (!unique.length) {
    return {
      kind: "network",
      status: "empty",
      severity: "info",
      summary: "No IPv4 or IPv6 addresses were resolved, so infrastructure enrichment was skipped.",
      data: { hosts: [] },
      raw: null,
    };
  }

  const hosts = await Promise.all(
    unique.map(async (ip) => {
      const [geoResult, shodanResult] = await Promise.all([ipwho(ip), shodanInternetDb(ip)]);
      const host = {
        ip,
        geo: geoResult.data,
        shodan: shodanResult.data,
        geoError: geoResult.error,
        shodanError: shodanResult.error,
      };

      if (ptr) {
        try {
          const ptrResult = await reverseDns(ip);
          host.ptr = ptrResult.values;
          host.ptrError = null;
        } catch (error) {
          host.ptr = [];
          host.ptrError = errorMessage(error);
        }
      }

      return host;
    })
  );

  const successful = hosts.filter((host) => host.geo || host.shodan || (host.ptr && host.ptr.length));
  const ports = hosts.reduce(
    (sum, host) => sum + (host.shodan && host.shodan.ports ? host.shodan.ports.length : 0),
    0
  );
  const signals = exposureSignals(hosts);

  return {
    kind: "network",
    status: successful.length ? "ok" : "empty",
    severity: signals.some((signal) => signal.severity === "attention")
      ? "attention"
      : signals.length
        ? "note"
        : "info",
    summary: successful.length
      ? `${hosts.length} address${hosts.length === 1 ? "" : "es"} enriched · ${ports} observed port${ports === 1 ? "" : "s"}`
      : "No enrichment data returned for the resolved addresses.",
    data: { hosts },
    raw: hosts,
    wide: true,
    signals,
  };
}

async function waybackFinding(target, label) {
  const url = `https://archive.org/wayback/available?url=${encodeURIComponent(target)}`;
  let data;

  try {
    data = await getJson(url, { timeout: 18000 });
  } catch (error) {
    const retryable =
      !(error instanceof HttpError) ||
      [429, 502, 503].includes(error.status);

    if (!retryable) throw error;
    await new Promise((resolve) => setTimeout(resolve, 900));
    data = await getJson(url, { timeout: 18000 });
  }

  const snapshot = data && data.archived_snapshots && data.archived_snapshots.closest;

  if (!snapshot) {
    return {
      kind: "archive",
      status: "empty",
      severity: "info",
      summary: "No Wayback Machine snapshot found.",
      data: { target, available: false },
      raw: data,
      wide: true,
    };
  }

  const snapshotUrl = snapshot.url
    ? snapshot.url.replace(/^http:\/\//i, "https://")
    : null;

  return {
    kind: "archive",
    status: "ok",
    severity: "info",
    summary: `Closest snapshot: ${waybackDate(snapshot.timestamp)} · HTTP ${snapshot.status || "unknown"}`,
    data: {
      target,
      available: true,
      url: snapshotUrl,
      timestamp: snapshot.timestamp || null,
      status: snapshot.status || null,
      label,
    },
    raw: data,
    wide: true,
  };
}

function pivotLink(label, url) {
  return { label, url };
}

function domainPivots(host, url) {
  const q = encodeURIComponent(host);
  const links = [
    pivotLink("Google", `https://www.google.com/search?q=site%3A${q}`),
    pivotLink("Bing", `https://www.bing.com/search?q=site%3A${q}`),
    pivotLink("GitHub", `https://github.com/search?q=${q}&type=code`),
    pivotLink("crt.sh", `https://crt.sh/?q=%25.${q}`),
    pivotLink("Shodan", `https://www.shodan.io/search?query=hostname%3A${q}`),
    pivotLink("Censys", `https://search.censys.io/search?resource=hosts&q=${q}`),
    pivotLink("urlscan", `https://urlscan.io/domain/${q}`),
    pivotLink("Wayback", `https://web.archive.org/web/*/${q}/*`),
    pivotLink("VirusTotal", `https://www.virustotal.com/gui/domain/${q}`),
  ];

  if (url) {
    links.unshift(
      pivotLink("Exact archive", `https://web.archive.org/web/*/${encodeURIComponent(url)}`),
      pivotLink("Safe Browsing", `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(url)}`)
    );
  }

  return links;
}

function ipPivots(ip) {
  const q = encodeURIComponent(ip);
  return [
    pivotLink("Shodan", `https://www.shodan.io/host/${q}`),
    pivotLink("Censys", `https://search.censys.io/hosts/${q}`),
    pivotLink("AbuseIPDB", `https://www.abuseipdb.com/check/${q}`),
    pivotLink("VirusTotal", `https://www.virustotal.com/gui/ip-address/${q}`),
    pivotLink("urlscan", `https://urlscan.io/ip/${q}`),
    pivotLink("IPinfo", `https://ipinfo.io/${q}`),
    pivotLink("Wayback", `https://web.archive.org/web/*/${q}/*`),
  ];
}

function usernamePivots(username) {
  const q = encodeURIComponent(username);
  return [
    pivotLink("GitHub", `https://github.com/${q}`),
    pivotLink("GitLab", `https://gitlab.com/${q}`),
    pivotLink("Codeberg", `https://codeberg.org/${q}`),
    pivotLink("Keybase", `https://keybase.io/${q}`),
    pivotLink("Hacker News", `https://news.ycombinator.com/user?id=${q}`),
    pivotLink("Reddit", `https://www.reddit.com/user/${q}`),
    pivotLink("X", `https://x.com/${q}`),
    pivotLink("Google", `https://www.google.com/search?q=%22${q}%22`),
  ];
}

function emailPivots(email) {
  const q = encodeURIComponent(email);
  const handle = email.split("@")[0];
  return [
    pivotLink("Have I Been Pwned", `https://haveibeenpwned.com/account/${q}`),
    pivotLink("Gravatar", `https://gravatar.com/${md5(email)}`),
    pivotLink("GitHub commits", `https://github.com/search?q=${encodeURIComponent(`author-email:${email}`)}&type=commits`),
    pivotLink("Google", `https://www.google.com/search?q=%22${q}%22`),
    pivotLink("GitHub users", `https://github.com/search?q=${encodeURIComponent(handle)}&type=users`),
  ];
}

function urlPivots(url, host) {
  return [
    pivotLink("urlscan", `https://urlscan.io/search/#${encodeURIComponent(url)}`),
    pivotLink("Wayback", `https://web.archive.org/web/*/${encodeURIComponent(url)}`),
    pivotLink("Safe Browsing", `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(url)}`),
    pivotLink("VirusTotal", `https://www.virustotal.com/gui/domain/${encodeURIComponent(host)}`),
    pivotLink("Google", `https://www.google.com/search?q=${encodeURIComponent(url)}`),
  ];
}

function pivotsFinding(links, title = "Pivot links") {
  return {
    kind: "pivots",
    status: "ok",
    severity: "info",
    summary: "Continue the investigation in external tools. Links open in a new tab.",
    data: { links },
    raw: null,
    wide: true,
  };
}

function profileSignals(profiles, checked) {
  const signals = [];

  if (profiles.length >= 3) {
    signals.push({
      severity: "note",
      title: "Handle reused across public platforms",
      detail: `${profiles.length} profiles matched this handle: ${profiles.map((profile) => profile.platform).join(", ")}. Confirm each account belongs to the same person.`,
    });
  }

  const github = profiles.find((profile) => profile.platform === "GitHub" && profile.joined);
  if (github) {
    const age = ageInDays(github.joined);
    if (age !== null && age <= 90) {
      signals.push({
        severity: "note",
        title: "Recently created GitHub account",
        detail: `The GitHub profile was created ${dateOnly(github.joined)} (${age} days ago).`,
      });
    }
  }

  const publicEmail = profiles.find((profile) => profile.email && !/noreply/i.test(profile.email));
  if (publicEmail) {
    signals.push({
      severity: "note",
      title: "Public contact email exposed",
      detail: `${publicEmail.platform} lists ${publicEmail.email} publicly.`,
    });
  }

  const failed = checked.filter((entry) => entry.status === "error").length;
  if (failed) {
    signals.push({
      severity: "info",
      title: "Some identity providers failed",
      detail: `${failed} provider${failed === 1 ? "" : "s"} did not respond. Absence of a profile in the remaining sources is not proof of absence.`,
    });
  }

  return signals;
}

async function lookupGithub(username, token) {
  try {
    const data = await getJson(
      `https://api.github.com/users/${encodeURIComponent(username)}`,
      { headers: githubHeaders(token), timeout: 15000 }
    );

    return {
      platform: "GitHub",
      username: data.login,
      displayName: data.name || data.login,
      bio: data.bio || "",
      location: data.location || "",
      email: data.email || "",
      joined: data.created_at || null,
      followers: data.followers,
      url: data.html_url,
      stats: [
        { label: "Repos", value: compactNumber(data.public_repos) },
        { label: "Followers", value: compactNumber(data.followers) },
        { label: "Following", value: compactNumber(data.following) },
      ],
      links: [
        data.blog ? { label: "Website", url: data.blog } : null,
        data.twitter_username ? { label: "X", url: `https://x.com/${data.twitter_username}` } : null,
      ].filter(Boolean),
      raw: data,
    };
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) return null;
    throw error;
  }
}

async function lookupGitlab(username) {
  const data = await getJson(
    `https://gitlab.com/api/v4/users?username=${encodeURIComponent(username)}`,
    { timeout: 15000 }
  );

  const user = Array.isArray(data) ? data[0] : null;
  if (!user) return null;

  return {
    platform: "GitLab",
    username: user.username,
    displayName: user.name || user.username,
    bio: user.bio || "",
    location: user.location || "",
    email: user.public_email || "",
    joined: user.created_at || null,
    followers: user.followers,
    url: user.web_url,
    stats: [
      { label: "Followers", value: compactNumber(user.followers) },
      { label: "Following", value: compactNumber(user.following) },
    ],
    links: user.website_url ? [{ label: "Website", url: user.website_url }] : [],
    raw: user,
  };
}

async function lookupKeybase(username) {
  const data = await getJson(
    `https://keybase.io/_/api/1.0/user/lookup.json?username=${encodeURIComponent(username)}&fields=basics,profile,proofs_summary`,
    { timeout: 15000 }
  );

  const them = data && data.them
    ? (Array.isArray(data.them) ? data.them[0] : data.them)
    : null;

  if (!data || !them || (data.status && data.status.code !== 0)) {
    return null;
  }
  const basics = them.basics || {};
  const profile = them.profile || {};
  const proofs = them.proofs_summary && them.proofs_summary.all ? them.proofs_summary.all : [];

  return {
    platform: "Keybase",
    username: basics.username || username,
    displayName: profile.full_name || basics.username || username,
    bio: profile.bio || "",
    location: profile.location || "",
    email: "",
    joined: basics.ctime ? new Date(basics.ctime * 1000).toISOString() : null,
    followers: null,
    url: `https://keybase.io/${encodeURIComponent(basics.username || username)}`,
    stats: [
      { label: "Proofs", value: compactNumber(proofs.length) },
      { label: "ID version", value: String(basics.id_version || "—") },
    ],
    links: profile.website ? [{ label: "Website", url: profile.website }] : [],
    raw: data,
  };
}

async function lookupHackerNews(username) {
  try {
    const data = await getJson(
      `https://hn.algolia.com/api/v1/users/${encodeURIComponent(username)}`,
      { timeout: 15000 }
    );

    if (!data || !data.username) return null;

    return {
      platform: "Hacker News",
      username: data.username,
      displayName: data.username,
      bio: data.about || "",
      location: "",
      email: "",
      joined: null,
      followers: null,
      url: `https://news.ycombinator.com/user?id=${encodeURIComponent(data.username)}`,
      stats: [{ label: "Karma", value: compactNumber(data.karma) }],
      links: [],
      raw: data,
    };
  } catch (error) {
    if (error instanceof HttpError && [404, 500].includes(error.status)) return null;
    throw error;
  }
}

async function lookupDevTo(username) {
  try {
    const data = await getJson(
      `https://dev.to/api/users/by_username?url=${encodeURIComponent(username)}`,
      { timeout: 15000 }
    );

    if (!data || !data.username) return null;

    return {
      platform: "dev.to",
      username: data.username,
      displayName: data.name || data.username,
      bio: data.summary || "",
      location: data.location || "",
      email: "",
      joined: data.joined_at || null,
      followers: null,
      url: `https://dev.to/${encodeURIComponent(data.username)}`,
      stats: [],
      links: [
        data.website_url ? { label: "Website", url: data.website_url } : null,
        data.twitter_username ? { label: "X", url: `https://x.com/${data.twitter_username}` } : null,
        data.github_username ? { label: "GitHub", url: `https://github.com/${data.github_username}` } : null,
      ].filter(Boolean),
      raw: data,
    };
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) return null;
    throw error;
  }
}

async function lookupCodeberg(username) {
  try {
    const data = await getJson(
      `https://codeberg.org/api/v1/users/${encodeURIComponent(username)}`,
      { timeout: 15000 }
    );

    if (!data || !data.login) return null;

    return {
      platform: "Codeberg",
      username: data.login,
      displayName: data.full_name || data.login,
      bio: data.description || "",
      location: data.location || "",
      email: data.email && !/noreply/i.test(data.email) ? data.email : "",
      joined: data.created || null,
      followers: data.followers_count,
      url: data.html_url || `https://codeberg.org/${encodeURIComponent(data.login)}`,
      stats: [
        { label: "Followers", value: compactNumber(data.followers_count) },
        { label: "Repos", value: compactNumber(data.starred_repos_count) },
      ],
      links: data.website ? [{ label: "Website", url: data.website }] : [],
      raw: data,
    };
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) return null;
    throw error;
  }
}

async function profileSweep(username, token) {
  const providers = [
    { label: "GitHub", lookup: () => lookupGithub(username, token) },
    { label: "GitLab", lookup: () => lookupGitlab(username) },
    { label: "Keybase", lookup: () => lookupKeybase(username) },
    { label: "Hacker News", lookup: () => lookupHackerNews(username) },
    { label: "dev.to", lookup: () => lookupDevTo(username) },
    { label: "Codeberg", lookup: () => lookupCodeberg(username) },
  ];

  const checked = await Promise.all(
    providers.map(async (provider) => {
      try {
        const profile = await provider.lookup();
        return profile
          ? { provider: provider.label, status: "found", profile }
          : { provider: provider.label, status: "not-found" };
      } catch (error) {
        return {
          provider: provider.label,
          status: "error",
          error: errorMessage(error),
        };
      }
    })
  );

  const foundProfiles = checked
    .filter((entry) => entry.status === "found")
    .map((entry) => entry.profile);
  const errors = checked.filter((entry) => entry.status === "error");

  if (!foundProfiles.length && errors.length === checked.length) {
    throw new Error(`All identity providers failed (${errors[0].error})`);
  }

  const raw = {};
  const profiles = foundProfiles.map(({ raw: providerRaw, ...profile }) => {
    raw[profile.platform] = providerRaw;
    return profile;
  });
  const signals = profileSignals(profiles, checked);

  return {
    kind: "profiles",
    status: profiles.length ? "ok" : "empty",
    severity: signals.some((signal) => signal.severity === "attention")
      ? "attention"
      : signals.length
        ? "note"
        : "info",
    summary: profiles.length
      ? `${profiles.length} public profile${profiles.length === 1 ? "" : "s"} found · ${profiles.map((profile) => profile.platform).join(", ")}`
      : `No public profiles matched this exact handle${errors.length ? `; ${errors.length} provider${errors.length === 1 ? "" : "s"} failed` : ""}.`,
    data: {
      username,
      profiles,
      checked: checked.map(({ provider, status, error }) => ({ provider, status, error })),
      note: "A missing profile only means this exact handle was not found by the queried API. It is not proof that the person does not exist.",
    },
    raw,
    wide: true,
    signals,
  };
}

function gravatarProfile(entry, email, hash) {
  const accounts = Array.isArray(entry.accounts) ? entry.accounts : [];
  const urls = Array.isArray(entry.urls) ? entry.urls : [];
  const photo = entry.thumbnailUrl || (Array.isArray(entry.photos) && entry.photos[0] && entry.photos[0].value) || null;

  return {
    email,
    hash,
    displayName: entry.displayName || entry.preferredUsername || null,
    about: entry.aboutMe || "",
    profileUrl: entry.profileUrl || `https://gravatar.com/${hash}`,
    photo,
    location: Array.isArray(entry.currentLocation) ? entry.currentLocation.join(", ") : "",
    accounts: accounts.map((account) => ({
      label: account.shortname || account.name || "Account",
      username: account.username || "",
      url: account.url || null,
    })),
    urls: urls.map((item) => ({
      label: item.title || "Link",
      url: item.value || null,
    })),
    raw: entry,
  };
}

async function gravatarLookup(email) {
  const hash = md5(email);
  const url = `https://gravatar.com/${hash}.json`;

  try {
    const data = await getJson(url, {
      headers: { Accept: "application/json" },
      timeout: 12000,
    });

    if (!data || data === "User not found") {
      return {
        kind: "gravatar",
        status: "empty",
        severity: "info",
        summary: "No public Gravatar profile linked to this email hash.",
        data: { email, hash, found: false },
        raw: data,
      };
    }

    const entry = Array.isArray(data.entry) ? data.entry[0] : null;
    if (!entry) {
      return {
        kind: "gravatar",
        status: "empty",
        severity: "info",
        summary: "No public Gravatar profile linked to this email hash.",
        data: { email, hash, found: false },
        raw: data,
      };
    }

    const profile = gravatarProfile(entry, email, hash);

    return {
      kind: "gravatar",
      status: "ok",
      severity: "note",
      summary: `Public Gravatar profile found${profile.displayName ? ` · ${profile.displayName}` : ""}.`,
      data: { email, hash, found: true, profile },
      raw: data,
      signals: [{
        severity: "note",
        title: "Email linked to a public Gravatar profile",
        detail: "The email hash resolves to a publicly accessible Gravatar profile. This is a deliberate public exposure, but it can correlate the address to an identity.",
      }],
    };
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) {
      return {
        kind: "gravatar",
        status: "empty",
        severity: "info",
        summary: "No public Gravatar profile linked to this email hash.",
        data: { email, hash, found: false },
        raw: null,
      };
    }
    throw error;
  }
}

async function githubCommitSearch(email, token) {
  const query = encodeURIComponent(`author-email:${email}`);
  const url = `https://api.github.com/search/commits?q=${query}&per_page=5&sort=author-date&order=desc`;

  try {
    const data = await getJson(url, { headers: githubHeaders(token), timeout: 20000 });
    const total = Number(data.total_count || 0);
    const items = Array.isArray(data.items) ? data.items : [];

    if (!total) {
      return {
        kind: "commits",
        status: "empty",
        severity: "info",
        summary: "No public GitHub commits matched this author email.",
        data: { email, totalCount: 0, commits: [] },
        raw: data,
        wide: true,
      };
    }

    const commits = items.map((item) => ({
      repo: item.repository ? item.repository.full_name : "unknown",
      message: item.commit && item.commit.message ? item.commit.message.split("\n")[0] : "",
      author: item.commit && item.commit.author ? item.commit.author.name : "",
      date: item.commit && item.commit.author ? item.commit.author.date : null,
      url: item.html_url || null,
    }));

    return {
      kind: "commits",
      status: "ok",
      severity: "note",
      summary: `${compactNumber(total)} public commit${total === 1 ? "" : "s"} matched this author email.`,
      data: {
        email,
        totalCount: total,
        commits,
        searchUrl: `https://github.com/search?q=${query}&type=commits`,
        note: "Git commit author emails are self-declared and can be spoofed or inherited from repository history.",
      },
      raw: data,
      wide: true,
      signals: [{
        severity: "note",
        title: "Email associated with public GitHub commits",
        detail: `${compactNumber(total)} commit${total === 1 ? "" : "s"} use this author email. Check whether the association is expected.`,
      }],
    };
  } catch (error) {
    if (error instanceof HttpError && error.status === 422) {
      return {
        kind: "commits",
        status: "empty",
        severity: "info",
        summary: "GitHub rejected this commit search.",
        data: { email, totalCount: 0, commits: [] },
        raw: null,
        wide: true,
      };
    }
    throw error;
  }
}

function urlAnatomy(url, hadCredentials) {
  const parsed = new URL(url);
  const query = [...parsed.searchParams.entries()].map(([key, value]) => ({ key, value }));
  const hostname = parsed.hostname;
  const tracking = query.filter(({ key }) =>
    /^(utm_|fbclid$|gclid$|dclid$|mc_cid$|mc_eid$|ref$|ref_src$|igshid$)/i.test(key)
  );
  const sensitiveKeys = query.filter(({ key }) =>
    /(token|key|secret|password|passwd|auth|session|sig|signature)/i.test(key)
  );
  const isShortener = SHORTENERS.has(hostname.toLowerCase());
  const isPunycode = hostname.toLowerCase().split(".").some((label) => label.startsWith("xn--"));

  const signals = [];

  if (parsed.protocol === "http:") {
    signals.push({
      severity: "attention",
      title: "Unencrypted HTTP URL",
      detail: "Traffic to this URL is not protected by TLS. Credentials or session data could be exposed on the network.",
    });
  }

  if (isPunycode) {
    signals.push({
      severity: "attention",
      title: "Punycode hostname",
      detail: "The hostname contains an internationalized label. Verify the rendered domain carefully for homograph impersonation.",
    });
  }

  if (isShortener) {
    signals.push({
      severity: "note",
      title: "URL shortener detected",
      detail: `${hostname} is a known link shortener. Resolve the final destination before trusting the link.`,
    });
  }

  if (hadCredentials) {
    signals.push({
      severity: "attention",
      title: "Credentials embedded in URL",
      detail: "The submitted URL contained a username or password. Credentials were removed from the report target, but URLs should never carry secrets.",
    });
  }

  if (sensitiveKeys.length) {
    signals.push({
      severity: "note",
      title: "Sensitive-looking query parameters",
      detail: `Parameter names suggest secrets or tokens: ${sensitiveKeys.map((entry) => entry.key).join(", ")}. Values are included in the local report; handle it carefully.`,
    });
  }

  if (tracking.length) {
    signals.push({
      severity: "info",
      title: "Tracking parameters present",
      detail: `${tracking.length} campaign or click-tracking parameter${tracking.length === 1 ? "" : "s"} found.`,
    });
  }

  return {
    kind: "url-anatomy",
    status: "ok",
    severity: signals.some((signal) => signal.severity === "attention")
      ? "attention"
      : signals.length
        ? "note"
        : "info",
    summary: `${parsed.protocol.replace(":", "").toUpperCase()} · ${hostname} · ${parsed.pathname || "/"}`,
    data: {
      url,
      scheme: parsed.protocol.replace(":", ""),
      hostname,
      port: parsed.port || null,
      path: parsed.pathname || "/",
      query,
      fragment: parsed.hash || null,
      hasCredentials: Boolean(hadCredentials),
      isIpHost: isIp(hostname),
      isPunycode,
      isShortener,
      trackingParameters: tracking.map((entry) => entry.key),
      sourceUrl: url,
    },
    raw: null,
    wide: true,
    signals,
  };
}

function readAssociatedRoot(host) {
  return isIp(host) ? host : rootDomain(host);
}

function buildReport(target, type, meta, findings, errors, startedAt) {
  const sorted = [...findings].sort((a, b) => (a.order || 0) - (b.order || 0));
  const signals = sorted.flatMap((finding) =>
    (finding.signals || []).map((signal) => ({
      ...signal,
      source: finding.source,
      finding: finding.title,
    }))
  );

  return {
    tool: {
      name: "ORBIT",
      version: TOOL_VERSION,
      mode: "client-side",
    },
    target,
    type,
    typeLabel: typeLabel(type),
    generatedAt: new Date().toISOString(),
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    meta,
    findings: sorted,
    signals,
    errors,
    disclaimer:
      "Public-record OSINT can be incomplete, stale, or self-declared. Absence of evidence is not evidence of absence. Use only on authorized targets.",
  };
}

async function addFinding(context, meta, producer) {
  try {
    const finding = await producer();
    context.findings.push({
      id: meta.id,
      title: meta.title,
      source: meta.source,
      sourceUrl: meta.sourceUrl || null,
      order: meta.order || 0,
      ...finding,
    });
  } catch (error) {
    context.errors.push({
      id: meta.id,
      title: meta.title,
      source: meta.source,
      message: errorMessage(error),
    });
  }
}

async function runDomain(context, host, { url = null } = {}) {
  const root = rootDomain(host);
  context.meta.rootDomain = root;

  const dnsPromise = lookupDns(host);
  const mailDomain = root;

  await Promise.all([
    addFinding(
      context,
      {
        id: "dns",
        title: "DNS records",
        source: "Cloudflare DoH",
        sourceUrl: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
        order: 10,
      },
      async () => buildDnsFinding(host, await dnsPromise)
    ),
    addFinding(
      context,
      {
        id: "rdap",
        title: "Registration record",
        source: "RDAP",
        sourceUrl: `https://rdap.org/domain/${encodeURIComponent(root)}`,
        order: 20,
      },
      async () => {
        const raw = await rdapLookup("domain", root);
        return parseRdapDomain(raw, root);
      }
    ),
    addFinding(
      context,
      {
        id: "certs",
        title: "Certificate transparency",
        source: "crt.sh",
        sourceUrl: `https://crt.sh/?q=${encodeURIComponent(`%.${root}`)}`,
        order: 30,
      },
      async () => certificateLookup(root)
    ),
    addFinding(
      context,
      {
        id: "mail",
        title: "Mail authentication",
        source: "Cloudflare DoH",
        sourceUrl: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(mailDomain)}&type=TXT`,
        order: 25,
      },
      async () => buildMailFinding(await mailPosture(mailDomain))
    ),
    addFinding(
      context,
      {
        id: "network",
        title: "Network exposure",
        source: "ipwho.is + Shodan InternetDB",
        sourceUrl: "https://internetdb.shodan.io/",
        order: 50,
      },
      async () => {
        const dns = await dnsPromise;
        const ips = [...dns.A.values, ...dns.AAAA.values];
        return buildNetworkFinding(ips);
      }
    ),
    addFinding(
      context,
      {
        id: "archive",
        title: "Archive history",
        source: "Wayback Machine",
        sourceUrl: `https://web.archive.org/web/*/${encodeURIComponent(url || host)}`,
        order: 60,
      },
      async () => waybackFinding(url || host, url ? "exact URL" : "domain")
    ),
    addFinding(
      context,
      {
        id: "pivots",
        title: "Pivot links",
        source: "Manual pivot",
        sourceUrl: null,
        order: 90,
      },
      async () => pivotsFinding(url ? [...urlPivots(url, host), ...domainPivots(host, url)] : domainPivots(host))
    ),
  ]);
}

async function runIp(context, ip) {
  context.meta.rootDomain = ip;
  const [geoResult, rdapResult, shodanResult, ptrResult] = await Promise.allSettled([
    ipwho(ip),
    rdapLookup("ip", ip),
    shodanInternetDb(ip),
    reverseDns(ip),
  ]);

  await Promise.all([
    addFinding(
      context,
      {
        id: "ip-geo",
        title: "IP geolocation",
        source: "ipwho.is",
        sourceUrl: `https://ipwho.is/${encodeURIComponent(ip)}`,
        order: 10,
      },
      async () => {
        if (geoResult.status === "rejected") throw geoResult.reason;
        const result = geoResult.value;
        if (result.error) throw new Error(result.error);
        if (!result.data) {
          return {
            kind: "ip-geo",
            status: "empty",
            severity: "info",
            summary: "No geolocation data returned for this IP.",
            data: null,
            raw: null,
          };
        }

        const data = result.data;
        const location = [data.city, data.region, data.country].filter(Boolean).join(", ");
        const connection = data.connection || {};

        return {
          kind: "ip-geo",
          status: "ok",
          severity: "info",
          summary: [
            location || "Location unknown",
            connection.asn ? `AS${connection.asn}` : null,
            connection.org || connection.isp || null,
          ].filter(Boolean).join(" · "),
          data,
          raw: data,
          wide: true,
        };
      }
    ),
    addFinding(
      context,
      {
        id: "ip-rdap",
        title: "Network registration",
        source: "RDAP",
        sourceUrl: `https://rdap.org/ip/${encodeURIComponent(ip)}`,
        order: 20,
      },
      async () => {
        if (rdapResult.status === "rejected") throw rdapResult.reason;
        const raw = rdapResult.value;
        const events = eventMap(raw.events);
        const org = (raw.entities || [])
          .map((entity) => vcardValue(entity, "fn"))
          .find(Boolean);

        return {
          kind: "ip-rdap",
          status: "ok",
          severity: "info",
          summary: [
            raw.name || "Unnamed network",
            raw.country || null,
            raw.startAddress && raw.endAddress ? `${raw.startAddress} – ${raw.endAddress}` : null,
          ].filter(Boolean).join(" · "),
          data: {
            name: raw.name || null,
            handle: raw.handle || null,
            startAddress: raw.startAddress || null,
            endAddress: raw.endAddress || null,
            country: raw.country || null,
            type: raw.type || null,
            parentHandle: raw.parentHandle || null,
            organization: org || null,
            registered: events.registration || null,
            updated: events["last changed"] || null,
            status: Array.isArray(raw.status) ? raw.status : [],
            rdapUrl: `https://rdap.org/ip/${encodeURIComponent(ip)}`,
          },
          raw,
        };
      }
    ),
    addFinding(
      context,
      {
        id: "shodan",
        title: "Observed services",
        source: "Shodan InternetDB",
        sourceUrl: `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
        order: 30,
      },
      async () => {
        if (shodanResult.status === "rejected") throw shodanResult.reason;
        const result = shodanResult.value;
        if (result.error) throw new Error(result.error);
        if (!result.data) {
          return {
            kind: "shodan",
            status: "empty",
            severity: "info",
            summary: "No InternetDB record returned for this IP.",
            data: null,
            raw: null,
          };
        }

        const data = result.data;
        const signals = exposureSignals([{ ip, shodan: data }]);

        return {
          kind: "shodan",
          status: "ok",
          severity: signals.some((signal) => signal.severity === "attention")
            ? "attention"
            : signals.length
              ? "note"
              : "info",
          summary: [
            `${(data.ports || []).length} observed port${(data.ports || []).length === 1 ? "" : "s"}`,
            `${(data.hostnames || []).length} hostname${(data.hostnames || []).length === 1 ? "" : "s"}`,
            (data.vulns || []).length ? `${(data.vulns || []).length} CVE${(data.vulns || []).length === 1 ? "" : "s"}` : null,
          ].filter(Boolean).join(" · "),
          data,
          raw: data,
          wide: true,
          signals,
        };
      }
    ),
    addFinding(
      context,
      {
        id: "ptr",
        title: "Reverse DNS",
        source: "Cloudflare DoH",
        sourceUrl: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(ip)}&type=PTR`,
        order: 25,
      },
      async () => {
        if (ptrResult.status === "rejected") throw ptrResult.reason;
        const data = ptrResult.value;
        return {
          kind: "ptr",
          status: data.values.length ? "ok" : "empty",
          severity: "info",
          summary: data.values.length ? data.values.join(" · ") : "No PTR record returned.",
          data: { ip, names: data.values },
          raw: data,
        };
      }
    ),
    addFinding(
      context,
      {
        id: "pivots",
        title: "Pivot links",
        source: "Manual pivot",
        sourceUrl: null,
        order: 90,
      },
      async () => pivotsFinding(ipPivots(ip))
    ),
  ]);
}

async function runUsername(context, username) {
  context.meta.rootDomain = null;

  await Promise.all([
    addFinding(
      context,
      {
        id: "profiles",
        title: "Profile sweep",
        source: "GitHub + 5 providers",
        sourceUrl: "https://github.com/",
        order: 10,
      },
      async () => profileSweep(username, context.options.githubToken)
    ),
    addFinding(
      context,
      {
        id: "pivots",
        title: "Pivot links",
        source: "Manual pivot",
        sourceUrl: null,
        order: 90,
      },
      async () => pivotsFinding(usernamePivots(username))
    ),
  ]);
}

async function runEmail(context, email) {
  const domain = email.split("@")[1];
  const root = rootDomain(domain);
  context.meta.rootDomain = root;

  await Promise.all([
    addFinding(
      context,
      {
        id: "gravatar",
        title: "Gravatar profile",
        source: "Gravatar",
        sourceUrl: `https://gravatar.com/${md5(email)}`,
        order: 10,
      },
      async () => gravatarLookup(email)
    ),
    addFinding(
      context,
      {
        id: "mail",
        title: "Mail authentication",
        source: "Cloudflare DoH",
        sourceUrl: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
        order: 20,
      },
      async () => buildMailFinding(await mailPosture(domain))
    ),
    addFinding(
      context,
      {
        id: "commits",
        title: "Public GitHub commits",
        source: "GitHub",
        sourceUrl: `https://github.com/search?q=${encodeURIComponent(`author-email:${email}`)}&type=commits`,
        order: 30,
      },
      async () => githubCommitSearch(email, context.options.githubToken)
    ),
    addFinding(
      context,
      {
        id: "pivots",
        title: "Pivot links",
        source: "Manual pivot",
        sourceUrl: null,
        order: 90,
      },
      async () => pivotsFinding(emailPivots(email))
    ),
  ]);
}

async function runUrl(context, url, rawTarget) {
  let hadCredentials = false;
  try {
    const raw = new URL(rawTarget);
    hadCredentials = Boolean(raw.username || raw.password);
  } catch {
    hadCredentials = false;
  }

  const parsed = new URL(url);
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  context.meta.rootDomain = readAssociatedRoot(host);

  await addFinding(
    context,
    {
      id: "url-anatomy",
      title: "URL anatomy",
      source: "URL parser",
      sourceUrl: url,
      order: 5,
    },
    async () => urlAnatomy(url, hadCredentials)
  );

  if (isIp(host)) {
    await runIp(context, host);
    context.meta.rootDomain = null;
    await addFinding(
      context,
      {
        id: "url-pivots",
        title: "URL pivots",
        source: "Manual pivot",
        sourceUrl: null,
        order: 91,
      },
      async () => pivotsFinding(urlPivots(url, host))
    );
  } else {
    await runDomain(context, host, { url });
  }
}

export async function investigate(rawTarget, requestedType = "auto", options = {}) {
  const startedAt = performance.now();
  const target = normalizeTarget(rawTarget, requestedType);
  const type =
    requestedType && requestedType !== "auto" ? requestedType : detectType(rawTarget);

  if (type === "unknown") {
    throw new Error("Could not identify that target.");
  }

  const context = {
    target,
    type,
    options,
    meta: {},
    findings: [],
    errors: [],
  };

  if (type === "domain") {
    await runDomain(context, target);
  } else if (type === "ip") {
    await runIp(context, target);
  } else if (type === "username") {
    await runUsername(context, target);
  } else if (type === "email") {
    await runEmail(context, target);
  } else if (type === "url") {
    await runUrl(context, target, rawTarget);
  } else {
    throw new Error("Unsupported target type.");
  }

  return buildReport(target, type, context.meta, context.findings, context.errors, startedAt);
}
