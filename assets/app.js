import {
  detectType,
  investigate,
  normalizeTarget,
  typeLabel,
} from "./modules.js";
import { toJson, toMarkdown } from "./report.js";

const KEYS = {
  history: "orbit.history.v1",
  token: "orbit.github-token.v1",
  raw: "orbit.show-raw.v1",
};

const TYPE_CYCLE = ["auto", "domain", "ip", "username", "email", "url"];
const SEVERITY_RANK = { attention: 0, note: 1, info: 2 };
const PLATFORM_MARKS = {
  GitHub: "GH",
  GitLab: "GL",
  Keybase: "KB",
  "Hacker News": "HN",
  "dev.to": "DEV",
  Codeberg: "CB",
};

const dom = {
  scopeLabel: document.querySelector("#scopeLabel"),
  scopeCheck: document.querySelector("#scopeCheck"),
  scopeError: document.querySelector("#scopeError"),
  searchForm: document.querySelector("#searchForm"),
  targetInput: document.querySelector("#targetInput"),
  detectPill: document.querySelector("#detectPill"),
  runBtn: document.querySelector("#runBtn"),
  emptyState: document.querySelector("#emptyState"),
  loadingState: document.querySelector("#loadingState"),
  resultView: document.querySelector("#resultView"),
  resultsPanel: document.querySelector("#resultsPanel"),
  loadingTarget: document.querySelector("#loadingTarget"),
  scanSteps: document.querySelector("#scanSteps"),
  resultType: document.querySelector("#resultType"),
  resultTimestamp: document.querySelector("#resultTimestamp"),
  resultTarget: document.querySelector("#resultTarget"),
  resultMeta: document.querySelector("#resultMeta"),
  statsRow: document.querySelector("#statsRow"),
  signalList: document.querySelector("#signalList"),
  errorPanel: document.querySelector("#errorPanel"),
  cards: document.querySelector("#cards"),
  historyList: document.querySelector("#historyList"),
  railCount: document.querySelector("#railCount"),
  clearHistory: document.querySelector("#clearHistory"),
  copyJson: document.querySelector("#copyJson"),
  exportJson: document.querySelector("#exportJson"),
  exportMd: document.querySelector("#exportMd"),
  runAgain: document.querySelector("#runAgain"),
  settingsBtn: document.querySelector("#settingsBtn"),
  footerSettings: document.querySelector("#footerSettings"),
  settingsDialog: document.querySelector("#settingsDialog"),
  settingsForm: document.querySelector("#settingsForm"),
  closeSettings: document.querySelector("#closeSettings"),
  githubToken: document.querySelector("#githubToken"),
  showRawDefault: document.querySelector("#showRawDefault"),
  clearLocal: document.querySelector("#clearLocal"),
  toast: document.querySelector("#toast"),
};

const state = {
  overrideType: "auto",
  report: null,
  history: [],
  token: storageGet(KEYS.token) || "",
  showRaw: storageGet(KEYS.raw) === "1",
  running: false,
  stepTimer: null,
};

let toastTimer = null;

function storageGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(key, value) {
  try {
    if (value === null || value === undefined || value === "") {
      window.localStorage.removeItem(key);
    } else {
      window.localStorage.setItem(key, value);
    }
  } catch {
    // Local storage can be unavailable in hardened browser modes.
  }
}

function storageRemove(key) {
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Ignore.
  }
}

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;

    if (key === "class") {
      node.className = value;
    } else if (key === "text") {
      node.textContent = String(value);
    } else if (key === "dataset") {
      Object.assign(node.dataset, value);
    } else if (key === "on") {
      for (const [event, handler] of Object.entries(value)) {
        node.addEventListener(event, handler);
      }
    } else if (value === true) {
      node.setAttribute(key, "");
    } else {
      node.setAttribute(key, String(value));
    }
  }

  const items = Array.isArray(children) ? children : [children];
  for (const child of items) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }

  return node;
}

function safeExternalUrl(value) {
  if (!value) return null;
  const raw = String(value).trim();

  try {
    const url = new URL(raw);
    if (url.protocol === "http:" || url.protocol === "https:") return url.href;
  } catch {
    // Try to repair a bare hostname below.
  }

  if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/.*)?$/i.test(raw)) {
    return `https://${raw}`;
  }

  return null;
}

function link(url, text, className = "") {
  const href = safeExternalUrl(url);
  if (!href) return el("span", { class: className, text: text || "—" });
  return el("a", {
    class: className,
    href,
    target: "_blank",
    rel: "noopener noreferrer",
    text: text || href,
  });
}

function tag(value, tone = "", title = null) {
  return el("span", {
    class: `tag${tone ? ` ${tone}` : ""}`,
    text: value,
    title: title || undefined,
  });
}

function tagList(values, tone = "", limit = 0) {
  const wrap = el("div", { class: "tag-row" });
  if (!Array.isArray(values) || !values.length) return wrap;

  const shown = limit > 0 ? values.slice(0, limit) : values;
  for (const value of shown) wrap.append(tag(value, tone));

  if (limit > 0 && values.length > limit) {
    wrap.append(tag(`+${values.length - limit} more`));
  }

  return wrap;
}

function mono(value) {
  return el("span", { class: "mono", text: value });
}

function kv(rows) {
  const wrap = el("div", { class: "kv" });

  for (const [label, value] of rows) {
    if (value === null || value === undefined || value === "") continue;
    if (Array.isArray(value) && value.length === 0) continue;

    const row = el("div", { class: "kv-row" });
    row.append(el("div", { class: "kv-key", text: label }));

    const val = el("div", { class: "kv-val" });
    if (value instanceof Node) {
      val.append(value);
    } else if (Array.isArray(value)) {
      val.append(document.createTextNode(value.join(", ")));
    } else {
      val.textContent = String(value);
    }

    row.append(val);
    wrap.append(row);
  }

  return wrap;
}

function chips(links) {
  const wrap = el("div", { class: "chips" });
  if (!Array.isArray(links)) return wrap;

  for (const item of links) {
    const href = safeExternalUrl(item.url);
    if (!href) continue;
    wrap.append(
      el("a", {
        class: "chip-link",
        href,
        target: "_blank",
        rel: "noopener noreferrer",
      }, [
        item.label,
        el("span", { text: "↗", "aria-hidden": "true" }),
      ])
    );
  }

  return wrap;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toISOString().slice(0, 10);
}

function formatDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatRelative(value) {
  if (!value) return "";
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) return "";
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  if (seconds < 60) return "now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

function formatWaybackTimestamp(value) {
  const raw = String(value || "");
  if (/^\d{14}$/.test(raw)) {
    return `${raw.slice(0, 4)}-${raw.slice(4, 6)}-${raw.slice(6, 8)} ${raw.slice(8, 10)}:${raw.slice(10, 12)} UTC`;
  }
  return formatDate(value);
}

function showToast(message, type = "") {
  window.clearTimeout(toastTimer);
  dom.toast.textContent = message;
  dom.toast.className = `toast show${type ? ` ${type}` : ""}`;
  toastTimer = window.setTimeout(() => {
    dom.toast.className = "toast";
  }, 4200);
}

function requireAuthorization() {
  if (dom.scopeCheck.checked) return true;

  dom.scopeLabel.classList.remove("attention");
  void dom.scopeLabel.offsetWidth;
  dom.scopeLabel.classList.add("attention");
  dom.scopeError.hidden = false;
  dom.scopeCheck.focus({ preventScroll: true });
  showToast("Confirm you have authorization before investigating.", "error");
  window.setTimeout(() => dom.scopeLabel.classList.remove("attention"), 1300);
  return false;
}

function updateTypePill() {
  const override = state.overrideType;

  if (override === "auto") {
    const detected = detectType(dom.targetInput.value);
    dom.detectPill.textContent = detected === "unknown" ? "AUTO" : typeLabel(detected);
    dom.detectPill.classList.remove("solid");
    dom.detectPill.title = "Type detected automatically. Click to override.";
  } else {
    dom.detectPill.textContent = typeLabel(override);
    dom.detectPill.classList.add("solid");
    dom.detectPill.title = "Manual type override. Click to cycle.";
  }
}

function cycleType() {
  const current = TYPE_CYCLE.indexOf(state.overrideType);
  state.overrideType = TYPE_CYCLE[(current + 1) % TYPE_CYCLE.length];
  updateTypePill();
  showToast(
    state.overrideType === "auto"
      ? "Target type set to automatic detection."
      : `Target type forced to ${typeLabel(state.overrideType)}.`
  );
}

function showView(view) {
  dom.emptyState.hidden = view !== "empty";
  dom.loadingState.hidden = view !== "loading";
  dom.resultView.hidden = view !== "result";
}

function prepareLoading(type) {
  const stepsByType = {
    domain: ["DNS", "RDAP", "Certificates", "Mail posture", "Infrastructure", "Archive"],
    ip: ["Geolocation", "RDAP", "InternetDB", "Reverse DNS", "Pivots"],
    username: ["GitHub", "GitLab", "Keybase", "Hacker News", "dev.to", "Codeberg"],
    email: ["Gravatar", "Mail posture", "GitHub commits", "Pivots"],
    url: ["URL anatomy", "DNS", "RDAP", "Certificates", "Infrastructure", "Archive"],
    unknown: ["Resolving", "Sources", "Report"],
  };

  const steps = stepsByType[type] || stepsByType.unknown;
  dom.scanSteps.replaceChildren(
    ...steps.map((step, index) =>
      el("span", {
        class: index === 0 ? "active" : "",
        text: step,
      })
    )
  );

  window.clearInterval(state.stepTimer);
  let index = 0;
  state.stepTimer = window.setInterval(() => {
    const items = [...dom.scanSteps.children];
    if (index < items.length) items[index].classList.add("done");
    index += 1;
    if (index < items.length) {
      items[index].classList.add("active");
    } else {
      window.clearInterval(state.stepTimer);
      state.stepTimer = null;
    }
  }, 900);
}

function stopLoadingSteps(success) {
  window.clearInterval(state.stepTimer);
  state.stepTimer = null;
  const items = [...dom.scanSteps.children];
  items.forEach((item, index) => {
    item.classList.toggle("done", Boolean(success));
    if (success || index === items.length - 1) item.classList.remove("active");
  });
}

function resultSources(report) {
  return new Set(report.findings.map((finding) => finding.source)).size;
}

function renderReport(report) {
  dom.resultType.textContent = report.typeLabel || typeLabel(report.type);
  dom.resultTimestamp.textContent = formatDateTime(report.generatedAt);
  dom.resultTarget.textContent = report.target;

  const root = report.meta && report.meta.rootDomain;
  const sourceCount = resultSources(report);
  dom.resultMeta.textContent = [
    root && root !== report.target ? `root ${root}` : null,
    `${report.findings.length} finding${report.findings.length === 1 ? "" : "s"}`,
    `${sourceCount} source${sourceCount === 1 ? "" : "s"}`,
    `${report.durationMs} ms`,
  ]
    .filter(Boolean)
    .join(" · ");

  renderStats(report);
  renderSignals(report);
  renderErrors(report);
  renderCards(report);
}

function renderStats(report) {
  const returned = report.findings.filter((finding) => finding.status === "ok").length;
  const attention = report.signals.filter((signal) => signal.severity === "attention").length;
  const notes = report.signals.filter((signal) => signal.severity === "note").length;
  const elapsed =
    report.durationMs >= 1000
      ? `${(report.durationMs / 1000).toFixed(1)}s`
      : `${report.durationMs}ms`;

  const stats = [
    {
      label: "RETURNED",
      value: `${returned}/${report.findings.length}`,
      className: returned ? "good" : "",
      title: "Modules that returned public data",
    },
    {
      label: "SIGNALS",
      value: String(report.signals.length),
      className: attention ? "attention" : notes ? "good" : "",
      title: `${attention} attention · ${notes} note-level`,
    },
    {
      label: "SOURCES",
      value: String(resultSources(report)),
      className: "",
      title: "Distinct public sources with data",
    },
    {
      label: "ELAPSED",
      value: elapsed,
      className: "",
      title: "End-to-end browser lookup time",
    },
  ];

  dom.statsRow.replaceChildren(
    ...stats.map((stat) =>
      el("div", {
        class: `stat ${stat.className}`,
        title: stat.title,
      }, [
        el("span", { text: stat.label }),
        el("strong", { text: stat.value }),
      ])
    )
  );
}

function renderSignals(report) {
  const signals = [...report.signals].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
  );

  if (!signals.length) {
    dom.signalList.replaceChildren(
      el("div", { class: "signal-item" }, [
        el("span", { class: "signal-mark info" }),
        el("div", { class: "signal-copy" }, [
          el("strong", { text: "No high-signal anomalies from available sources" }),
          el("p", { text: "This does not mean the target is secure. It means these public sources produced no attention or note-level findings." }),
        ]),
      ])
    );
    return;
  }

  const shown = signals.slice(0, 10);
  const nodes = shown.map((signal) =>
    el("div", { class: "signal-item" }, [
      el("span", { class: `signal-mark ${signal.severity}` }),
      el("div", { class: "signal-copy" }, [
        el("strong", { text: signal.title }),
        el("p", { text: signal.detail }),
        el("small", { text: `Source: ${signal.source || "—"}` }),
      ]),
    ])
  );

  if (signals.length > shown.length) {
    nodes.push(
      el("div", { class: "signal-item" }, [
        el("span", { class: "signal-mark info" }),
        el("div", { class: "signal-copy" }, [
          el("strong", { text: `${signals.length - shown.length} more signals` }),
          el("p", { text: "The complete signal list is included in the exported report." }),
        ]),
      ])
    );
  }

  dom.signalList.replaceChildren(...nodes);
}

function renderErrors(report) {
  if (!report.errors.length) {
    dom.errorPanel.hidden = true;
    dom.errorPanel.replaceChildren();
    return;
  }

  dom.errorPanel.hidden = false;
  const items = report.errors.map((error) =>
    el("div", { class: "error-item" }, [
      el("span", { class: "source", text: error.source }),
      el("span", { text: `${error.title}: ${error.message}` }),
    ])
  );

  dom.errorPanel.replaceChildren(
    el("strong", { text: `SOURCE FAILURES · ${report.errors.length}` }),
    ...items
  );
}

function renderCards(report) {
  const findings = [...report.findings].sort((a, b) => (a.order || 0) - (b.order || 0));
  dom.cards.replaceChildren(...findings.map(renderCard));
}

function renderCard(finding) {
  const article = el("article", {
    class: `card${finding.wide ? " wide" : ""}`,
    dataset: { kind: finding.kind },
  });

  const source = finding.sourceUrl
    ? link(finding.sourceUrl, finding.source, "card-source")
    : el("span", { class: "card-source", text: finding.source });

  const head = el("div", { class: "card-head" }, [
    el("div", { class: "card-title-wrap" }, [
      source,
      el("h3", { class: "card-title", text: finding.title }),
    ]),
    el("span", {
      class: `card-status ${finding.status}`,
      text: finding.status === "ok" ? "RETURNED" : "NO DATA",
    }),
  ]);

  const body = el("div", { class: "card-body" });
  if (finding.summary) {
    body.append(el("p", { class: "card-summary", text: finding.summary }));
  }
  body.append(renderFindingBody(finding));
  body.append(renderRaw(finding));

  article.append(head, body);
  return article;
}

function renderRaw(finding) {
  const raw = finding.raw === null || finding.raw === undefined ? finding.data : finding.raw;
  if (raw === null || raw === undefined) return document.createDocumentFragment();

  let text;
  try {
    text = JSON.stringify(raw, null, 2);
  } catch {
    text = String(raw);
  }

  if (text.length > 150000) {
    text = `${text.slice(0, 150000)}\n\n… output truncated in the UI. Use JSON export for the full record.`;
  }

  const details = el("details", { class: "raw", open: state.showRaw });
  details.append(
    el("summary", { text: "Raw provider data" }),
    el("pre", { text })
  );
  return details;
}

function renderFindingBody(finding) {
  switch (finding.kind) {
    case "dns":
      return renderDns(finding.data);
    case "rdap-domain":
      return renderRdapDomain(finding.data);
    case "certs":
      return renderCerts(finding.data);
    case "mail":
      return renderMail(finding.data);
    case "network":
      return renderNetwork(finding.data);
    case "ip-geo":
      return renderIpGeo(finding.data);
    case "ip-rdap":
      return renderIpRdap(finding.data);
    case "shodan":
      return renderShodan(finding.data);
    case "ptr":
      return renderPtr(finding.data);
    case "archive":
      return renderArchive(finding.data);
    case "profiles":
      return renderProfiles(finding.data);
    case "gravatar":
      return renderGravatar(finding.data);
    case "commits":
      return renderCommits(finding.data);
    case "url-anatomy":
      return renderUrlAnatomy(finding.data);
    case "pivots":
      return chips(finding.data.links);
    default:
      return el("pre", { class: "raw", text: JSON.stringify(finding.data, null, 2) });
  }
}

function renderDns(data) {
  const wrap = el("div");
  const order = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA", "SOA"];

  for (const type of order) {
    const result = data.records && data.records[type];
    if (!result) continue;
    if (!result.values.length && !result.error) continue;

    const group = el("div", { class: "record-group" });
    group.append(el("div", { class: "record-type", text: type }));

    if (result.error) {
      group.append(el("p", { class: "empty-note", text: `Query failed: ${result.error}` }));
    } else {
      group.append(tagList(result.values, "mono", 16));
    }

    wrap.append(group);
  }

  if (!wrap.childElementCount) {
    wrap.append(el("p", { class: "empty-note", text: "No DNS records were returned." }));
  }

  return wrap;
}

function renderRdapDomain(data) {
  const status = data.status && data.status.length ? tagList(data.status, "cyan") : null;

  return el("div", {}, [
    kv([
      ["Registrar", data.registrar],
      ["Registrar ID", data.registrarId],
      ["Registered", data.registered ? formatDate(data.registered) : null],
      ["Last changed", data.updated ? formatDate(data.updated) : null],
      ["Expires", data.expires ? formatDate(data.expires) : null],
      ["Nameservers", data.nameservers && data.nameservers.length ? tagList(data.nameservers) : null],
      ["DNSSEC", data.dnssec ? "signed" : "not indicated"],
      ["Status", status],
    ]),
  ]);
}

function renderCerts(data) {
  const wrap = el("div");
  wrap.append(
    kv([
      ["Certificates", compact(data.certificateCount)],
      ["Unique names", compact(data.uniqueNames)],
      ["Earliest issue", data.earliestIssue ? formatDate(data.earliestIssue) : null],
      ["Latest expiry", data.latestExpiry ? formatDate(data.latestExpiry) : null],
      ["Truncated", data.truncated ? "yes" : null],
    ])
  );

  if (data.interestingSubdomains && data.interestingSubdomains.length) {
    wrap.append(
      el("p", { class: "empty-note", text: "Potentially sensitive hostnames" }),
      tagList(data.interestingSubdomains, "amber", 12)
    );
  }

  if (data.subdomains && data.subdomains.length) {
    wrap.append(
      el("p", { class: "empty-note", text: `Subdomains (${data.subdomains.length})` }),
      tagList(data.subdomains, "", 40)
    );
  }

  return wrap;
}

function compact(value) {
  return Number(value || 0).toLocaleString("en-US");
}

function postureCell(label, value, status) {
  return el("div", { class: `posture ${status}` }, [
    el("span", { text: label }),
    el("strong", { text: value }),
  ]);
}

function renderMail(data) {
  const wrap = el("div");
  const mxStatus = data.nullMx || data.mx.length ? "ok" : "warn";
  const spfStatus = data.spf
    ? (data.spfAll && data.spfAll.startsWith("+") ? "bad" : "ok")
    : data.nullMx
      ? "ok"
      : "warn";
  const dmarcStatus = data.dmarc
    ? data.dmarcPolicy === "none"
      ? "warn"
      : "ok"
    : data.nullMx
      ? "ok"
      : "bad";

  wrap.append(
    el("div", { class: "mail-posture" }, [
      postureCell("MX", data.nullMx ? "NULL MX" : data.mx.length ? `${data.mx.length} record${data.mx.length === 1 ? "" : "s"}` : "MISSING", mxStatus),
      postureCell("SPF", data.spf ? (data.spfAll && data.spfAll.startsWith("+") ? "PERMISSIVE" : "FOUND") : data.nullMx ? "N/A" : "MISSING", spfStatus),
      postureCell("DMARC", data.dmarc ? String(data.dmarcPolicy || "FOUND").toUpperCase() : data.nullMx ? "N/A" : "MISSING", dmarcStatus),
    ])
  );

  wrap.append(
    kv([
      ["MX records", data.mx && data.mx.length ? tagList(data.mx) : data.nullMx ? "null MX" : null],
      ["SPF", data.spf],
      ["SPF all", data.spfAll],
      ["DMARC", data.dmarc],
    ])
  );

  return wrap;
}

function renderNetwork(data) {
  const wrap = el("div");

  if (!data.hosts || !data.hosts.length) {
    wrap.append(el("p", { class: "empty-note", text: "No resolved addresses to enrich." }));
    return wrap;
  }

  for (const host of data.hosts) {
    const block = el("div", { class: "host-block" });
    const head = el("div", { class: "host-head" }, [
      el("span", { class: "mono host-ip", text: host.ip }),
    ]);

    if (host.geo && host.geo.country_code) head.append(tag(host.geo.country_code, "lime"));
    if (host.shodan && host.shodan.ports && host.shodan.ports.length) {
      head.append(tag(`${host.shodan.ports.length} ports`, "cyan"));
    }
    if (host.shodan && host.shodan.vulns && host.shodan.vulns.length) {
      head.append(tag(`${host.shodan.vulns.length} CVEs`, "red"));
    }

    block.append(head);

    const geo = host.geo || {};
    const connection = geo.connection || {};
    const shodan = host.shodan || {};

    block.append(
      kv([
        ["Location", [geo.city, geo.region, geo.country].filter(Boolean).join(", ")],
        ["ASN", connection.asn ? `AS${connection.asn}` : null],
        ["Org", connection.org || connection.isp],
        ["Ports", shodan.ports && shodan.ports.length ? tagList(shodan.ports, "cyan", 16) : null],
        ["Hostnames", shodan.hostnames && shodan.hostnames.length ? tagList(shodan.hostnames, "", 10) : null],
        ["Tags", shodan.tags && shodan.tags.length ? tagList(shodan.tags, "amber") : null],
        ["CVEs", shodan.vulns && shodan.vulns.length ? tagList(shodan.vulns, "red", 12) : null],
        ["PTR", host.ptr && host.ptr.length ? tagList(host.ptr) : null],
        ["Errors", [host.geoError, host.shodanError, host.ptrError].filter(Boolean).join(" · ") || null],
      ])
    );

    wrap.append(block);
  }

  return wrap;
}

function renderIpGeo(data) {
  if (!data) return el("p", { class: "empty-note", text: "No geolocation data." });
  const connection = data.connection || {};
  const mapLink =
    data.latitude != null && data.longitude != null
      ? chips([{ label: "Open map", url: `https://www.openstreetmap.org/?mlat=${data.latitude}&mlon=${data.longitude}#map=10/${data.latitude}/${data.longitude}` }])
      : null;

  return el("div", {}, [
    kv([
      ["Location", [data.city, data.region, data.country].filter(Boolean).join(", ")],
      ["Continent", data.continent],
      ["ASN", connection.asn ? `AS${connection.asn}` : null],
      ["Organization", connection.org],
      ["ISP", connection.isp],
      ["Timezone", data.timezone && data.timezone.id],
      ["Coordinates", data.latitude != null ? `${data.latitude}, ${data.longitude}` : null],
    ]),
    mapLink,
  ]);
}

function renderIpRdap(data) {
  return kv([
    ["Network", data.name],
    ["Handle", data.handle],
    ["Range", data.startAddress && data.endAddress ? `${data.startAddress} – ${data.endAddress}` : null],
    ["Country", data.country],
    ["Type", data.type],
    ["Organization", data.organization],
    ["Registered", data.registered ? formatDate(data.registered) : null],
    ["Updated", data.updated ? formatDate(data.updated) : null],
    ["Status", data.status && data.status.length ? tagList(data.status, "cyan") : null],
  ]);
}

function renderShodan(data) {
  if (!data) return el("p", { class: "empty-note", text: "No InternetDB record." });
  return kv([
    ["IP", data.ip],
    ["Ports", data.ports && data.ports.length ? tagList(data.ports, "cyan", 24) : null],
    ["Hostnames", data.hostnames && data.hostnames.length ? tagList(data.hostnames, "", 12) : null],
    ["CPEs", data.cpes && data.cpes.length ? tagList(data.cpes, "", 8) : null],
    ["Tags", data.tags && data.tags.length ? tagList(data.tags, "amber") : null],
    ["CVEs", data.vulns && data.vulns.length ? tagList(data.vulns, "red") : null],
  ]);
}

function renderPtr(data) {
  return data.names && data.names.length
    ? tagList(data.names)
    : el("p", { class: "empty-note", text: "No PTR record returned." });
}

function renderArchive(data) {
  if (!data.available) {
    return el("p", { class: "empty-note", text: "No snapshot was returned by the Wayback availability API." });
  }

  return el("div", {}, [
    kv([
      ["Target", data.target],
      ["Snapshot", link(data.url, data.url)],
      ["Captured", formatWaybackTimestamp(data.timestamp)],
      ["HTTP status", data.status],
    ]),
  ]);
}

function renderProfiles(data) {
  const wrap = el("div");

  if (!data.profiles || !data.profiles.length) {
    wrap.append(el("p", { class: "empty-note", text: "No public profiles matched this exact handle." }));
  } else {
    const list = el("div", { class: "profile-list" });

    for (const profile of data.profiles) {
      const body = el("div", { class: "profile-body" });
      const name = link(
        profile.url,
        profile.displayName || profile.username,
        "profile-name"
      );

      body.append(
        el("div", { class: "profile-top" }, [
          name,
          el("span", { text: profile.platform }),
        ])
      );

      if (profile.bio) body.append(el("p", { text: profile.bio }));

      const meta = el("div", { class: "profile-meta" });
      if (profile.username) meta.append(mono(`@${profile.username}`));
      if (profile.location) meta.append(el("span", { text: profile.location }));
      if (profile.joined) meta.append(el("span", { text: `joined ${formatDate(profile.joined)}` }));
      for (const stat of profile.stats || []) {
        meta.append(el("span", { text: `${stat.label} ${stat.value}` }));
      }
      if (meta.childElementCount) body.append(meta);

      if (profile.links && profile.links.length) {
        body.append(chips(profile.links));
      }

      list.append(
        el("div", { class: "profile" }, [
          el("div", { class: "profile-icon", text: PLATFORM_MARKS[profile.platform] || profile.platform.slice(0, 2) }),
          body,
        ])
      );
    }

    wrap.append(list);
  }

  if (data.checked && data.checked.length) {
    const checked = el("div", { class: "tag-row checked-row" });
    for (const entry of data.checked) {
      if (entry.status === "found") continue;
      checked.append(
        tag(
          `${entry.provider} ${entry.status === "error" ? "error" : "not found"}`,
          entry.status === "error" ? "red" : "",
          entry.error || null
        )
      );
    }
    if (checked.childElementCount) wrap.append(checked);
  }

  if (data.note) wrap.append(el("p", { class: "empty-note", text: data.note }));
  return wrap;
}

function renderGravatar(data) {
  if (!data.found) {
    return el("p", { class: "empty-note", text: "No public Gravatar profile is linked to this email hash." });
  }

  const profile = data.profile;
  const wrap = el("div");
  const body = el("div", { class: "gravatar-body" });

  if (profile.displayName) {
    body.append(el("h4", { class: "gravatar-name", text: profile.displayName }));
  }
  if (profile.about) body.append(el("p", { class: "card-summary", text: profile.about }));

  const accountLinks = [];
  for (const account of profile.accounts || []) {
    accountLinks.push({
      label: `${account.label}${account.username ? `:${account.username}` : ""}`,
      url: account.url,
    });
  }
  for (const item of profile.urls || []) {
    accountLinks.push({ label: item.label, url: item.url });
  }
  if (accountLinks.length) body.append(chips(accountLinks));

  if (profile.profileUrl) {
    body.append(chips([{ label: "Gravatar profile", url: profile.profileUrl }]));
  }

  const avatarUrl = safeExternalUrl(profile.photo);
  if (avatarUrl) {
    wrap.append(
      el("div", { class: "gravatar-head" }, [
        el("img", {
          class: "avatar",
          src: avatarUrl,
          alt: "",
          loading: "lazy",
          referrerpolicy: "no-referrer",
        }),
        body,
      ])
    );
  } else {
    wrap.append(body);
  }

  return wrap;
}

function renderCommits(data) {
  if (!data.commits || !data.commits.length) {
    return el("p", { class: "empty-note", text: "No matching public commits." });
  }

  const wrap = el("div");
  if (data.searchUrl) {
    wrap.append(chips([{ label: `All ${compact(data.totalCount)} matches`, url: data.searchUrl }]));
  }

  const list = el("div", { class: "commit-list" });
  for (const commit of data.commits) {
    const item = el("div", { class: "commit" });
    const top = el("div", { class: "commit-top" }, [
      el("strong", { class: "mono", text: commit.repo }),
      el("span", { text: commit.date ? formatDate(commit.date) : "" }),
    ]);
    item.append(top, el("p", { class: "commit-message", text: commit.message || "(no message)" }));
    if (commit.url) item.append(link(commit.url, "Open commit ↗"));
    list.append(item);
  }
  wrap.append(list);

  if (data.note) wrap.append(el("p", { class: "empty-note", text: data.note }));
  return wrap;
}

function renderUrlAnatomy(data) {
  const wrap = el("div");

  wrap.append(
    kv([
      ["Scheme", data.scheme ? data.scheme.toUpperCase() : null],
      ["Hostname", data.hostname],
      ["Port", data.port],
      ["Path", data.path],
      ["Fragment", data.fragment],
      ["IP host", data.isIpHost ? "yes" : "no"],
      ["Punycode", data.isPunycode ? "yes" : "no"],
      ["Shortener", data.isShortener ? "yes" : "no"],
      ["Tracking", data.trackingParameters && data.trackingParameters.length ? tagList(data.trackingParameters, "cyan") : null],
    ])
  );

  if (data.query && data.query.length) {
    wrap.append(el("p", { class: "empty-note", text: "Query parameters" }));
    const rows = data.query.map((entry) =>
      el("div", { class: "query-row" }, [
        el("span", { class: "query-key mono", text: entry.key }),
        el("span", { class: "query-value mono", text: entry.value || "—" }),
      ])
    );
    wrap.append(el("div", { class: "query-list" }, rows));
  }

  wrap.append(
    el("p", {
      class: "empty-note",
      text: "ORBIT does not fetch page content. Arbitrary cross-origin reads are blocked by the browser, so use the pivot links for page-level checks.",
    })
  );

  return wrap;
}

function renderHistory() {
  dom.railCount.textContent = `${state.history.length} run${state.history.length === 1 ? "" : "s"}`;

  if (!state.history.length) {
    dom.historyList.replaceChildren(
      el("div", { class: "rail-empty" }, [
        el("strong", { text: "No runs yet" }),
        "Targets you investigate are listed here. Stored in this browser only.",
      ])
    );
    return;
  }

  const items = state.history.map((item) => {
    const active =
      state.report &&
      state.report.target === item.target &&
      state.report.type === item.type;
    const button = el("button", {
      type: "button",
      class: `rail-item${active ? " active" : ""}`,
      title: `Re-run ${item.target}`,
    }, [
      el("div", { class: "rail-item-top" }, [
        el("span", { class: "rail-item-target", text: item.target }),
        el("span", { class: "rail-item-time", text: formatRelative(item.timestamp) }),
      ]),
      el("div", { class: "rail-item-meta" }, [
        el("span", { class: "mini-type", text: typeLabel(item.type) }),
        el("span", { text: `${item.findings} findings` }),
        item.attention
          ? el("span", { class: "rail-attention", text: `${item.attention} attention` })
          : null,
      ]),
    ]);

    button.addEventListener("click", () => {
      dom.targetInput.value = item.target;
      state.overrideType = item.type;
      updateTypePill();
      execute(item.target, item.type);
    });

    return button;
  });

  dom.historyList.replaceChildren(...items);
}

function pushHistory(report) {
  const item = {
    target: report.target,
    type: report.type,
    timestamp: new Date().toISOString(),
    findings: report.findings.length,
    signals: report.signals.length,
    attention: report.signals.filter((signal) => signal.severity === "attention").length,
  };

  state.history = [
    item,
    ...state.history.filter(
      (entry) => !(entry.target === item.target && entry.type === item.type)
    ),
  ].slice(0, 20);

  storageSet(KEYS.history, JSON.stringify(state.history));
  renderHistory();
}

function loadHistory() {
  const raw = storageGet(KEYS.history);
  if (!raw) return;
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      state.history = parsed
        .filter((item) => item && typeof item.target === "string" && typeof item.type === "string")
        .slice(0, 20);
    }
  } catch {
    state.history = [];
  }
}

async function execute(rawTarget, forcedType) {
  if (state.running) return;
  if (!requireAuthorization()) return;

  let normalized;
  try {
    normalized = normalizeTarget(rawTarget, forcedType || "auto");
  } catch (error) {
    showToast(error.message, "error");
    dom.targetInput.focus();
    return;
  }

  state.running = true;
  dom.runBtn.disabled = true;
  dom.runBtn.querySelector("span").textContent = "Investigating";
  dom.loadingTarget.textContent = normalized;
  showView("loading");
  prepareLoading(
    forcedType && forcedType !== "auto" ? forcedType : detectType(normalized)
  );

  try {
    const report = await investigate(rawTarget, forcedType || "auto", {
      githubToken: state.token,
    });
    state.report = report;
    stopLoadingSteps(true);
    renderReport(report);
    pushHistory(report);
    showView("result");
    dom.resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    stopLoadingSteps(false);
    showView(state.report ? "result" : "empty");
    showToast(error.message || "Investigation failed.", "error");
  } finally {
    state.running = false;
    dom.runBtn.disabled = false;
    dom.runBtn.querySelector("span").textContent = "Investigate";
  }
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = el("a", { href: url, download: filename });
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function reportFilename(report, extension) {
  const safeTarget = report.target
    .replace(/^https?:\/\//i, "")
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  const date = report.generatedAt.slice(0, 10);
  return `orbit-${report.type}-${safeTarget || "target"}-${date}.${extension}`;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = el("textarea", { class: "sr-only" });
    area.value = text;
    document.body.append(area);
    area.select();
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } catch {
      copied = false;
    }
    area.remove();
    return copied;
  }
}

function saveSettings() {
  state.token = dom.githubToken.value.trim();
  state.showRaw = dom.showRawDefault.checked;

  if (state.token) {
    storageSet(KEYS.token, state.token);
  } else {
    storageRemove(KEYS.token);
  }

  storageSet(KEYS.raw, state.showRaw ? "1" : "0");
  showToast("Settings saved locally.");
}

function clearLocalData() {
  if (!window.confirm("Clear local run history, token, and display settings?")) return;

  storageRemove(KEYS.history);
  storageRemove(KEYS.token);
  storageRemove(KEYS.raw);
  state.history = [];
  state.token = "";
  state.showRaw = false;
  dom.githubToken.value = "";
  dom.showRawDefault.checked = false;
  renderHistory();
  showToast("Local ORBIT data cleared.");
}

function bindEvents() {
  dom.searchForm.addEventListener("submit", (event) => {
    event.preventDefault();
    execute(dom.targetInput.value, state.overrideType);
  });

  dom.targetInput.addEventListener("input", updateTypePill);

  dom.detectPill.addEventListener("click", cycleType);

  dom.scopeCheck.addEventListener("change", () => {
    if (!dom.scopeCheck.checked) return;
    dom.scopeLabel.classList.remove("attention");
    dom.scopeError.hidden = true;
  });

  document.querySelectorAll("[data-example]").forEach((button) => {
    button.addEventListener("click", () => {
      dom.targetInput.value = button.dataset.example;
      const requestedType = button.dataset.type;
      state.overrideType = requestedType && TYPE_CYCLE.includes(requestedType)
        ? requestedType
        : "auto";
      updateTypePill();
      dom.targetInput.focus();
    });
  });

  dom.clearHistory.addEventListener("click", () => {
    if (!state.history.length) return;
    if (!window.confirm("Clear local run history?")) return;
    state.history = [];
    storageRemove(KEYS.history);
    renderHistory();
    showToast("Run history cleared.");
  });

  dom.copyJson.addEventListener("click", async () => {
    if (!state.report) return;
    const copied = await copyText(toJson(state.report));
    showToast(copied ? "Report JSON copied." : "Clipboard copy failed.", copied ? "" : "error");
  });

  dom.exportJson.addEventListener("click", () => {
    if (!state.report) return;
    downloadFile(
      reportFilename(state.report, "json"),
      toJson(state.report),
      "application/json"
    );
    showToast("JSON report downloaded.");
  });

  dom.exportMd.addEventListener("click", () => {
    if (!state.report) return;
    downloadFile(
      reportFilename(state.report, "md"),
      toMarkdown(state.report),
      "text/markdown;charset=utf-8"
    );
    showToast("Markdown report downloaded.");
  });

  dom.runAgain.addEventListener("click", () => {
    if (!state.report) return;
    dom.targetInput.value = state.report.target;
    state.overrideType = state.report.type;
    updateTypePill();
    execute(state.report.target, state.report.type);
  });

  const openSettings = () => {
    dom.githubToken.value = state.token;
    dom.showRawDefault.checked = state.showRaw;
    dom.settingsDialog.showModal();
  };

  dom.settingsBtn.addEventListener("click", openSettings);
  dom.footerSettings.addEventListener("click", openSettings);
  dom.closeSettings.addEventListener("click", () => dom.settingsDialog.close());

  dom.settingsForm.addEventListener("submit", (event) => {
    event.preventDefault();
    saveSettings();
    dom.settingsDialog.close();
  });

  dom.clearLocal.addEventListener("click", clearLocalData);

  dom.settingsDialog.addEventListener("click", (event) => {
    if (event.target === dom.settingsDialog) dom.settingsDialog.close();
  });
}

function loadQueryTarget() {
  const params = new URLSearchParams(window.location.search);
  const target = params.get("target");
  if (!target) return;

  dom.targetInput.value = target;
  const requestedType = params.get("type");
  if (requestedType && TYPE_CYCLE.includes(requestedType)) {
    state.overrideType = requestedType;
  }
  updateTypePill();
}

function init() {
  loadHistory();
  loadQueryTarget();
  renderHistory();
  updateTypePill();
  bindEvents();
}

init();
