function md(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function list(values) {
  if (!Array.isArray(values) || values.length === 0) return "—";
  return values.map((value) => md(value)).join(", ");
}

function kvRows(pairs) {
  const rows = pairs.filter(([, value]) => value !== null && value !== undefined && value !== "");
  if (!rows.length) return "";
  return [
    "| Field | Value |",
    "| --- | --- |",
    ...rows.map(([key, value]) => `| ${md(key)} | ${md(value)} |`),
  ].join("\n");
}

function dnsTable(data) {
  if (!data || !data.records) return "";
  const blocks = [];

  for (const [type, result] of Object.entries(data.records)) {
    if (result.error) {
      blocks.push(`**${type}** — error: ${result.error}`);
      continue;
    }
    if (!result.values || !result.values.length) continue;
    blocks.push(`**${type}**\n\n${result.values.map((value) => `- \`${value}\``).join("\n")}`);
  }

  return blocks.length ? blocks.join("\n\n") : "No records returned.";
}

function profileList(profiles) {
  if (!Array.isArray(profiles) || !profiles.length) return "No public profiles found.";

  return profiles
    .map((profile) => {
      const lines = [
        `#### ${profile.platform} — ${profile.displayName || profile.username}`,
        `- URL: ${profile.url || "—"}`,
        `- Handle: \`${profile.username}\``,
        profile.bio ? `- Bio: ${md(profile.bio)}` : null,
        profile.location ? `- Location: ${md(profile.location)}` : null,
        profile.joined ? `- Joined: ${md(profile.joined)}` : null,
        profile.stats && profile.stats.length
          ? `- Stats: ${profile.stats.map((stat) => `${stat.label} ${stat.value}`).join(", ")}`
          : null,
        profile.links && profile.links.length
          ? `- Links: ${profile.links.map((link) => `${link.label} (${link.url})`).join(", ")}`
          : null,
      ].filter(Boolean);
      return lines.join("\n");
    })
    .join("\n\n");
}

function networkData(data) {
  if (!data || !Array.isArray(data.hosts) || !data.hosts.length) return "No address data returned.";

  return data.hosts
    .map((host) => {
      const geo = host.geo || {};
      const connection = geo.connection || {};
      const shodan = host.shodan || {};
      const lines = [
        `#### ${host.ip}`,
        geo.success
          ? `- Location: ${[geo.city, geo.region, geo.country].filter(Boolean).join(", ") || "—"}`
          : null,
        connection.asn ? `- ASN: AS${connection.asn} ${connection.org || connection.isp || ""}`.trim() : null,
        host.shodan
          ? `- Observed ports: ${list(shodan.ports)}`
          : null,
        host.shodan
          ? `- Hostnames: ${list(shodan.hostnames)}`
          : null,
        host.shodan && shodan.tags && shodan.tags.length
          ? `- Tags: ${list(shodan.tags)}`
          : null,
        host.shodan && shodan.vulns && shodan.vulns.length
          ? `- CVEs: ${list(shodan.vulns)}`
          : null,
        host.ptr && host.ptr.length ? `- PTR: ${list(host.ptr)}` : null,
        host.geoError ? `- Geolocation error: ${host.geoError}` : null,
        host.shodanError ? `- InternetDB error: ${host.shodanError}` : null,
      ].filter(Boolean);
      return lines.join("\n");
    })
    .join("\n\n");
}

function findingBody(finding) {
  const data = finding.data;

  switch (finding.kind) {
    case "dns":
      return dnsTable(data);

    case "rdap-domain":
      return kvRows([
        ["Root domain", data.query],
        ["Handle", data.handle],
        ["Registrar", data.registrar],
        ["Registrar ID", data.registrarId],
        ["Registered", data.registered],
        ["Last changed", data.updated],
        ["Expires", data.expires],
        ["Nameservers", list(data.nameservers)],
        ["DNSSEC", data.dnssec ? "signed" : "not indicated"],
        ["Status", list(data.status)],
      ]);

    case "certs":
      return [
        kvRows([
          ["Certificates (unexpired)", data.certificateCount],
          ["Unique names", data.uniqueNames],
          ["Earliest issue", data.earliestIssue],
          ["Latest expiry", data.latestExpiry],
          ["Truncated", data.truncated ? "yes" : "no"],
        ]),
        data.interestingSubdomains && data.interestingSubdomains.length
          ? `\n**Potentially sensitive hostnames**\n\n${data.interestingSubdomains.map((name) => `- \`${name}\``).join("\n")}`
          : "",
        data.subdomains && data.subdomains.length
          ? `\n**Subdomains (first 100)**\n\n${data.subdomains.slice(0, 100).map((name) => `- \`${name}\``).join("\n")}${data.subdomains.length > 100 ? `\n\n_…${data.subdomains.length - 100} more in the JSON export._` : ""}`
          : "",
      ].filter(Boolean).join("\n");

    case "mail":
      return kvRows([
        ["Domain", data.domain],
        ["MX", list(data.mx)],
        ["Null MX", data.nullMx ? "yes" : "no"],
        ["SPF", data.spf],
        ["SPF all", data.spfAll],
        ["DMARC", data.dmarc],
        ["DMARC policy", data.dmarcPolicy],
      ]);

    case "network":
      return networkData(data);

    case "ip-geo": {
      const connection = (data && data.connection) || {};
      return kvRows([
        ["IP", data.ip],
        ["Location", [data.city, data.region, data.country].filter(Boolean).join(", ")],
        ["Continent", data.continent],
        ["ASN", connection.asn ? `AS${connection.asn}` : null],
        ["Organization", connection.org],
        ["ISP", connection.isp],
        ["Timezone", data.timezone && data.timezone.id],
        ["Coordinates", data.latitude != null ? `${data.latitude}, ${data.longitude}` : null],
      ]);
    }

    case "ip-rdap":
      return kvRows([
        ["Network", data.name],
        ["Handle", data.handle],
        ["Range", data.startAddress && data.endAddress ? `${data.startAddress} – ${data.endAddress}` : null],
        ["Country", data.country],
        ["Type", data.type],
        ["Organization", data.organization],
        ["Registered", data.registered],
        ["Last changed", data.updated],
        ["Status", list(data.status)],
      ]);

    case "shodan":
      return kvRows([
        ["IP", data.ip],
        ["Ports", list(data.ports)],
        ["Hostnames", list(data.hostnames)],
        ["CPEs", list(data.cpes)],
        ["Tags", list(data.tags)],
        ["CVEs", list(data.vulns)],
      ]);

    case "ptr":
      return data.names && data.names.length
        ? data.names.map((name) => `- \`${name}\``).join("\n")
        : "No PTR record returned.";

    case "archive":
      return data.available
        ? kvRows([
            ["Target", data.target],
            ["Snapshot", data.url],
            ["Timestamp", data.timestamp],
            ["HTTP status", data.status],
          ])
        : "No snapshot found.";

    case "profiles":
      return `${profileList(data.profiles)}\n\n**Providers checked:** ${data.checked.map((entry) => `${entry.provider} (${entry.status})`).join(", ")}`;

    case "gravatar":
      return data.found
        ? kvRows([
            ["Display name", data.profile.displayName],
            ["About", data.profile.about],
            ["Profile", data.profile.profileUrl],
            ["Photo", data.profile.photo],
            ["Accounts", data.profile.accounts.map((account) => `${account.label}:${account.username}`).join(", ")],
            ["Links", data.profile.urls.map((link) => `${link.label}: ${link.url}`).join(", ")],
          ])
        : "No public Gravatar profile found.";

    case "commits": {
      if (!data.commits || !data.commits.length) return "No matching public commits.";
      return [
        `**Total matches:** ${data.totalCount}`,
        "",
        ...data.commits.map((commit) =>
          `- ${commit.date ? `\`${commit.date}\`` : ""} **${commit.repo}** — ${md(commit.message)}${commit.url ? ` ([commit](${commit.url}))` : ""}`.replace("  ", " ")
        ),
      ].join("\n");
    }

    case "url-anatomy":
      return [
        kvRows([
          ["URL", data.url],
          ["Scheme", data.scheme],
          ["Hostname", data.hostname],
          ["Port", data.port],
          ["Path", data.path],
          ["Fragment", data.fragment],
          ["IP host", data.isIpHost ? "yes" : "no"],
          ["Punycode", data.isPunycode ? "yes" : "no"],
          ["Shortener", data.isShortener ? "yes" : "no"],
          ["Tracking params", list(data.trackingParameters)],
        ]),
        data.query && data.query.length
          ? `\n**Query parameters**\n\n| Key | Value |\n| --- | --- |\n${data.query.map((entry) => `| ${md(entry.key)} | ${md(entry.value)} |`).join("\n")}`
          : "",
      ].filter(Boolean).join("\n");

    case "pivots":
      return data.links.map((link) => `- [${md(link.label)}](${link.url})`).join("\n");

    default:
      return `\`\`\`json\n${JSON.stringify(data, null, 2)}\n\`\`\``;
  }
}

export function toMarkdown(report) {
  const lines = [
    `# ORBIT OSINT Report — ${report.target}`,
    "",
    kvRows([
      ["Target", report.target],
      ["Type", report.typeLabel],
      ["Generated", report.generatedAt],
      ["Duration", `${report.durationMs} ms`],
      ["Tool", `${report.tool.name} ${report.tool.version} (${report.tool.mode})`],
      ["Root domain", report.meta && report.meta.rootDomain],
    ]),
    "",
    `> ${report.disclaimer}`,
    "",
    "## Key signals",
    "",
    report.signals.length
      ? report.signals
          .map(
            (signal) =>
              `- **${signal.severity.toUpperCase()}** — ${signal.title}\n  - ${signal.detail}\n  - Source: ${signal.source || "—"}`
          )
          .join("\n")
      : "No attention or note-level signals were produced by the available sources.",
    "",
    "## Findings",
    "",
  ];

  for (const finding of report.findings) {
    lines.push(`### ${finding.title}`);
    lines.push("");
    lines.push(`- **Source:** ${finding.source}`);
    if (finding.sourceUrl) lines.push(`- **Source URL:** ${finding.sourceUrl}`);
    lines.push(`- **Status:** ${finding.status}`);
    lines.push(`- **Summary:** ${finding.summary}`);
    lines.push("");
    const body = findingBody(finding);
    if (body) {
      lines.push(body);
      lines.push("");
    }
  }

  if (report.errors.length) {
    lines.push("## Errors");
    lines.push("");
    for (const error of report.errors) {
      lines.push(`- **${error.source} / ${error.title}:** ${error.message}`);
    }
    lines.push("");
  }

  lines.push("## Sources consulted");
  lines.push("");
  const sources = [...new Set(report.findings.map((finding) => finding.source))];
  for (const source of sources) lines.push(`- ${source}`);
  if (report.errors.length) {
    for (const source of [...new Set(report.errors.map((error) => error.source))]) {
      lines.push(`- ${source} (failed)`);
    }
  }

  lines.push("");
  lines.push(`_Generated ${report.generatedAt} by ORBIT._`);
  lines.push("");

  return lines.join("\n");
}

export function toJson(report) {
  return JSON.stringify(report, null, 2);
}
