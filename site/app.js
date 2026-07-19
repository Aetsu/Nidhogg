"use strict";

const PAGE_SIZE = 25;
const INDEX_URL = "data/index.json";
const dayUrl = (date) => `data/${date}.json`;

const dateFmt = new Intl.DateTimeFormat("en-US", {
  day: "2-digit",
  month: "short",
});
const dateTimeFmt = new Intl.DateTimeFormat("en-US", {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  timeZone: "UTC",
});

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderStatsLine(data) {
  const line = document.getElementById("statsLine");
  const { total_packages, malicious, clean } = data.stats;
  line.textContent =
    `${total_packages.toLocaleString("en-US")} packages watched · ` +
    `${malicious.toLocaleString("en-US")} suspicious · ` +
    `${clean.toLocaleString("en-US")} clean`;

  const generated = document.getElementById("generatedAt");
  generated.textContent = `Updated ${dateTimeFmt.format(new Date(data.generated_at))} UTC`;
}

function isMalicious(pkg) {
  return pkg.findings.some((f) => f.domain_threat);
}

function renderSpine(packages, onSelect) {
  const spine = document.getElementById("spine");
  const startLabel = document.getElementById("spineDateStart");
  const endLabel = document.getElementById("spineDateEnd");

  if (packages.length === 0) {
    startLabel.textContent = "—";
    endLabel.textContent = "—";
    return;
  }

  const timestamps = packages.map((p) => new Date(p.analyzed_at).getTime());
  const min = Math.min(...timestamps);
  const max = Math.max(...timestamps);
  const span = max - min || 1;

  startLabel.textContent = dateFmt.format(new Date(min));
  endLabel.textContent = dateFmt.format(new Date(max));

  packages.forEach((pkg, index) => {
    const t = new Date(pkg.analyzed_at).getTime();
    const leftPct = ((t - min) / span) * 100;
    const mark = el("button", null);
    mark.type = "button";
    mark.className = `spine__mark ${isMalicious(pkg) ? "spine__mark--malicious" : "spine__mark--clean"}`;
    mark.style.left = `${leftPct}%`;
    mark.style.animationDelay = `${Math.min(index * 12, 600)}ms`;
    mark.title = pkg.name;
    mark.addEventListener("click", () => onSelect(pkg.name));
    spine.appendChild(mark);
  });
}

function cssEscape(value) {
  return value.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function httpStatusClass(status) {
  if (status >= 200 && status < 300) return "http-badge--ok";
  if (status >= 300 && status < 400) return "http-badge--redir";
  if (status >= 400 && status < 600) return "http-badge--err";
  return "http-badge--other";
}

function urlCell(finding) {
  const cell = el("td", "cell-url");
  cell.appendChild(el("span", "url-value", finding.url));

  const status = finding.http_status;
  const title = finding.http_title;
  const cert = finding.cert_issuer;
  const hasStatus = status !== null && status !== undefined;
  const hasTitle = Boolean(title);
  const hasCert = Boolean(cert);

  if (!hasStatus && !hasTitle && !hasCert) return cell;

  const enrich = el("div", "url-enrich");
  if (hasStatus) {
    enrich.appendChild(
      el("span", `http-badge ${httpStatusClass(status)}`, String(status)),
    );
  }
  if (hasTitle) {
    enrich.appendChild(el("span", "enrich-title", title));
  }
  if (hasCert) {
    enrich.appendChild(
      cert.includes("Let's Encrypt")
        ? el("span", "le-badge", "LE")
        : el("span", "cert-text", cert),
    );
  }
  cell.appendChild(enrich);
  return cell;
}

function inlineLink(href, text, className) {
  const link = el("a", className, text);
  link.href = href;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

function encodeFilePath(path) {
  return path.split("/").map(encodeURIComponent).join("/");
}

// inspector.pypi.io serves one page per distribution archive at
// /project/<name>/<version>/packages/<sharded-path-from-the-download-url>/,
// and one page per file inside it by appending the file's own path within
// that archive (see https://github.com/pypi/inspector inspector/main.py).
function inspectorDistributionUrl(pkg) {
  if (!pkg.version || !pkg.download_url) return null;
  let distPath;
  try {
    distPath = new URL(pkg.download_url).pathname;
  } catch {
    return null;
  }
  const base = `https://inspector.pypi.io/project/${encodeURIComponent(pkg.name)}/${encodeURIComponent(pkg.version)}`;
  return `${base}${distPath}/`;
}

function nameCell(pkg) {
  const cell = el("td", "cell-name");
  cell.appendChild(el("span", "pkg-name-value", pkg.name));
  cell.appendChild(
    isMalicious(pkg)
      ? el("span", "badge badge--malicious", "suspicious")
      : el("span", "badge badge--clean", "clean"),
  );

  const encodedName = encodeURIComponent(pkg.name);
  const encodedVersion = pkg.version ? encodeURIComponent(pkg.version) : null;
  const pypiUrl = encodedVersion
    ? `https://pypi.org/project/${encodedName}/${encodedVersion}/`
    : `https://pypi.org/project/${encodedName}/`;

  const inspectorUrl =
    inspectorDistributionUrl(pkg) ||
    (encodedVersion ? `https://inspector.pypi.io/project/${encodedName}/${encodedVersion}/` : null);

  const links = el("div", "pkg-links");
  links.appendChild(inlineLink(pypiUrl, "PyPI", "pkg-link"));
  if (inspectorUrl) {
    links.appendChild(inlineLink(inspectorUrl, "Inspector", "pkg-link"));
  }
  cell.appendChild(links);

  return cell;
}

function findingCells(finding, pkg) {
  const fileText = `${finding.file}:${finding.line}`;
  const distUrl = inspectorDistributionUrl(pkg);
  const file = el("td", "cell-mono cell-file");
  if (distUrl) {
    file.appendChild(
      inlineLink(`${distUrl}${encodeFilePath(finding.file)}`, fileText, "file-link"),
    );
  } else {
    file.appendChild(document.createTextNode(fileText));
  }
  const url = urlCell(finding);
  const tags = tagsCell(finding);
  return [file, url, tags];
}

function tagsCell(finding) {
  const cell = el("td", "cell-tags");
  cell.appendChild(el("span", "tag-badge tag-badge--layer", finding.layer));
  if (finding.method) {
    cell.appendChild(el("span", "tag-badge tag-badge--method", finding.method));
  }
  if (finding.domain_threat) {
    cell.appendChild(el("span", "tag-badge tag-badge--threat", finding.domain_threat));
  }
  return cell;
}

function emptyFindingCells() {
  return [
    el("td", "cell-mono cell-file cell-muted", "—"),
    el("td", "cell-url cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
  ];
}

function renderResultsTable(packages) {
  const tbody = document.getElementById("resultsBody");
  tbody.replaceChildren();

  packages.forEach((pkg, pkgIndex) => {
    const rowCount = Math.max(pkg.findings.length, 1);
    const groupClass = pkgIndex % 2 === 0 ? "group-a" : "group-b";

    for (let i = 0; i < rowCount; i += 1) {
      const rowClass = isMalicious(pkg)
        ? `result-row ${groupClass} pkg-malicious`
        : `result-row ${groupClass}`;
      const row = el("tr", rowClass);
      row.dataset.pkg = cssEscape(pkg.name);

      if (i === 0) {
        const pkgNameCell = nameCell(pkg);
        const dateCell = el(
          "td",
          "cell-mono cell-date",
          dateTimeFmt.format(new Date(pkg.analyzed_at)),
        );
        if (rowCount > 1) {
          [pkgNameCell, dateCell].forEach((cell) => {
            cell.rowSpan = rowCount;
          });
        }
        row.append(pkgNameCell, dateCell);
      }

      const cells =
        pkg.findings.length > 0
          ? findingCells(pkg.findings[i], pkg)
          : emptyFindingCells();
      row.append(...cells);
      tbody.appendChild(row);
    }
  });
}

const NONE_KEY = "__none__";

const FACET_DEFS = [
  { id: "status", field: "http_status", key: (v) => (v === null || v === undefined ? NONE_KEY : String(v)), noneLabel: "No status" },
  { id: "cert", field: "cert_issuer", key: (v) => (v ? v : NONE_KEY), noneLabel: "No cert" },
  { id: "layer", field: "layer", key: (v) => (v === null || v === undefined ? NONE_KEY : String(v)), noneLabel: "Unknown" },
  { id: "method", field: "method", key: (v) => (v ? v : NONE_KEY), noneLabel: "Plain literal" },
  { id: "threat", field: "domain_threat", key: (v) => (v ? v : NONE_KEY), noneLabel: "No threat" },
];

function collectFacetOptions(packages) {
  const findings = packages.flatMap((pkg) => pkg.findings);
  const options = {};
  FACET_DEFS.forEach((def) => {
    const counts = new Map();
    findings.forEach((finding) => {
      const raw = finding[def.field];
      const key = def.key(raw);
      const label = key === NONE_KEY ? def.noneLabel : String(raw);
      const entry = counts.get(key) ?? { key, label, count: 0 };
      entry.count += 1;
      counts.set(key, entry);
    });
    const sorted = [...counts.values()].sort((a, b) => {
      if (a.key === NONE_KEY) return 1;
      if (b.key === NONE_KEY) return -1;
      return a.label.localeCompare(b.label, "en", { numeric: true });
    });
    options[def.id] = sorted;
  });
  return options;
}

const BINARY_FACET_DEFS = [
  { id: "signed", field: "signed", key: (v) => (v === null ? NONE_KEY : String(v)), noneLabel: "Unknown" },
  { id: "format", field: "format", key: (v) => (v ? v : NONE_KEY), noneLabel: "Unknown" },
];

function flattenBinaryRows(binaryGroups) {
  return (binaryGroups ?? []).flatMap((group) =>
    group.binaries.map((bin) => ({
      package: group.package,
      analyzed_at: group.analyzed_at,
      ...bin,
    })),
  );
}

function signedBadgeClass(signed) {
  if (signed === true) return "badge--clean";
  if (signed === false) return "badge--malicious";
  return "badge--unknown";
}

function signedBadgeText(signed) {
  if (signed === true) return "signed";
  if (signed === false) return "unsigned";
  return "unknown";
}

function sha256Cell(bin) {
  const cell = el("td", "cell-mono cell-hash");
  const hashSpan = el("span", "hash-value", `${bin.sha256.slice(0, 12)}…`);
  hashSpan.title = bin.sha256;
  cell.appendChild(hashSpan);

  const copyBtn = el("button", "copy-btn", "copy");
  copyBtn.type = "button";
  copyBtn.setAttribute("aria-label", "Copy SHA-256 hash");
  copyBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(bin.sha256).then(() => {
      const original = copyBtn.textContent;
      copyBtn.textContent = "copied";
      copyBtn.disabled = true;
      setTimeout(() => {
        copyBtn.textContent = original;
        copyBtn.disabled = false;
      }, 1200);
    });
  });
  cell.appendChild(copyBtn);

  cell.appendChild(
    inlineLink(
      `https://www.virustotal.com/gui/file/${bin.sha256}`,
      "VT",
      "vt-link",
    ),
  );

  return cell;
}

function binaryCells(bin) {
  return [
    el("td", "cell-mono", bin.name),
    el("td", "cell-mono", bin.format),
    sha256Cell(bin),
    (() => {
      const cell = el("td");
      cell.appendChild(
        el("span", `badge ${signedBadgeClass(bin.signed)}`, signedBadgeText(bin.signed)),
      );
      return cell;
    })(),
    el("td", "cell-mono", bin.signer ?? "—"),
  ];
}

function emptyBinaryCells() {
  return [
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
  ];
}

function renderBinariesTable(groups) {
  const tbody = document.getElementById("binariesBody");
  tbody.replaceChildren();

  groups.forEach((group, groupIndex) => {
    const rowCount = Math.max(group.binaries.length, 1);
    const groupClass = groupIndex % 2 === 0 ? "group-a" : "group-b";

    for (let i = 0; i < rowCount; i += 1) {
      const row = el("tr", `result-row ${groupClass}`);

      if (i === 0) {
        const pkgNameCell = el("td", "cell-name", group.package);
        const dateCell = el(
          "td",
          "cell-mono cell-date",
          dateTimeFmt.format(new Date(group.analyzed_at)),
        );
        if (rowCount > 1) {
          [pkgNameCell, dateCell].forEach((cell) => {
            cell.rowSpan = rowCount;
          });
        }
        row.append(pkgNameCell, dateCell);
      }

      const cells =
        group.binaries.length > 0 ? binaryCells(group.binaries[i]) : emptyBinaryCells();
      row.append(...cells);
      tbody.appendChild(row);
    }
  });
}

function collectBinaryFacetOptions(rows) {
  const options = {};
  BINARY_FACET_DEFS.forEach((def) => {
    const counts = new Map();
    rows.forEach((row) => {
      const raw = row[def.field];
      const key = def.key(raw);
      const label = key === NONE_KEY ? def.noneLabel : String(raw);
      const entry = counts.get(key) ?? { key, label, count: 0 };
      entry.count += 1;
      counts.set(key, entry);
    });
    options[def.id] = [...counts.values()].sort((a, b) => a.label.localeCompare(b.label));
  });
  return options;
}

function binaryMatchesFacets(bin, facets) {
  return BINARY_FACET_DEFS.every((def) => {
    const selected = facets[def.id];
    if (selected.size === 0) return true;
    return selected.has(def.key(bin[def.field]));
  });
}

function applyBinaryFilters(binaryGroups, query, onlyWithBinaries, facets) {
  const needle = query.trim().toLowerCase();
  const facetsActive = BINARY_FACET_DEFS.some((def) => facets[def.id].size > 0);

  return (binaryGroups ?? [])
    .map((group) => {
      if (!facetsActive) return group;
      return {
        ...group,
        binaries: group.binaries.filter((b) => binaryMatchesFacets(b, facets)),
      };
    })
    .filter((group) => {
      if (needle && !group.package.toLowerCase().includes(needle)) return false;
      if ((onlyWithBinaries || facetsActive) && group.binaries.length === 0) return false;
      return true;
    });
}

function renderFacetMenu(def, options, selected, onChange) {
  const menu = document.getElementById(`${def.id}FilterMenu`);
  const count = document.getElementById(`${def.id}FilterCount`);
  menu.replaceChildren();

  if (options.length === 0) {
    menu.appendChild(el("p", "filter__empty", "No values for this day"));
  } else {
    options.forEach((opt) => {
      const label = el("label", "filter__option");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = opt.key;
      checkbox.checked = selected.has(opt.key);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) selected.add(opt.key);
        else selected.delete(opt.key);
        onChange();
      });
      label.appendChild(checkbox);
      label.appendChild(el("span", null, opt.label));
      label.appendChild(el("span", "filter__option-count", String(opt.count)));
      menu.appendChild(label);
    });
  }

  count.textContent = selected.size > 0 ? String(selected.size) : "";
}

function findingMatchesFacets(finding, facets) {
  return FACET_DEFS.every((def) => {
    const selected = facets[def.id];
    if (selected.size === 0) return true;
    return selected.has(def.key(finding[def.field]));
  });
}

function applyFilters(packages, query, urlOnly, facets) {
  const needle = query.trim().toLowerCase();
  const facetsActive = FACET_DEFS.some((def) => facets[def.id].size > 0);

  return packages
    .map((pkg) => {
      if (!facetsActive) return pkg;
      return { ...pkg, findings: pkg.findings.filter((f) => findingMatchesFacets(f, facets)) };
    })
    .filter((pkg) => {
      if (needle && !pkg.name.toLowerCase().includes(needle)) return false;
      if ((urlOnly || facetsActive) && pkg.findings.length === 0) return false;
      return true;
    });
}

function paginate(packages, page) {
  const totalPages = Math.max(Math.ceil(packages.length / PAGE_SIZE), 1);
  const clampedPage = Math.min(Math.max(page, 1), totalPages);
  const start = (clampedPage - 1) * PAGE_SIZE;
  return {
    page: clampedPage,
    totalPages,
    slice: packages.slice(start, start + PAGE_SIZE),
  };
}

const THREAT_ORDER = [
  "shortener",
  "tunneling",
  "exfiltration",
  "ip_recon",
  "malware_hosting",
  "suspicious_tld",
  "punycode",
];

function computeThreatCounts(packages) {
  const counts = new Map();
  packages
    .flatMap((pkg) => pkg.findings)
    .forEach((finding) => {
      if (!finding.domain_threat) return;
      counts.set(finding.domain_threat, (counts.get(finding.domain_threat) ?? 0) + 1);
    });
  return THREAT_ORDER.filter((key) => counts.has(key))
    .map((key) => ({
      label: key,
      count: counts.get(key),
      color: `var(--series-${THREAT_ORDER.indexOf(key) + 1})`,
    }))
    .sort((a, b) => b.count - a.count);
}

function computeVerdictCounts(stats) {
  return [
    { label: "clean", count: stats.clean, color: "var(--accent-clean)" },
    { label: "suspicious", count: stats.malicious, color: "var(--accent-malicious)" },
  ].filter((entry) => entry.count > 0);
}

function renderBarChart(mountEl, entries) {
  mountEl.replaceChildren();
  if (entries.length === 0) return;

  const rowHeight = 28;
  const barMaxWidth = 420;
  const labelGap = 8;
  const viewWidth = barMaxWidth + 220;
  const height = entries.length * rowHeight;
  const maxCount = Math.max(...entries.map((entry) => entry.count));
  const svgNs = "http://www.w3.org/2000/svg";

  const svg = document.createElementNS(svgNs, "svg");
  svg.setAttribute("viewBox", `0 0 ${viewWidth} ${height}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", String(height));
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Bar chart");

  entries.forEach((entry, index) => {
    const barWidth = Math.max((entry.count / maxCount) * barMaxWidth, 2);
    const y = index * rowHeight;

    const rect = document.createElementNS(svgNs, "rect");
    rect.setAttribute("x", "0");
    rect.setAttribute("y", String(y + 4));
    rect.setAttribute("width", String(barWidth));
    rect.setAttribute("height", String(rowHeight - 10));
    rect.setAttribute("rx", "2");
    rect.setAttribute("fill", entry.color);

    const title = document.createElementNS(svgNs, "title");
    title.textContent = `${entry.label}: ${entry.count}`;
    rect.appendChild(title);

    const text = document.createElementNS(svgNs, "text");
    text.setAttribute("x", String(barWidth + labelGap));
    text.setAttribute("y", String(y + rowHeight / 2 + 4));
    text.setAttribute("class", "chart-label");
    text.textContent = `${entry.label} — ${entry.count}`;

    svg.appendChild(rect);
    svg.appendChild(text);
  });

  mountEl.appendChild(svg);
}

const FORMAT_ORDER = ["pe", "macho", "elf"];
const FORMAT_LABELS = { pe: "PE", macho: "Mach-O", elf: "ELF", unknown: "unknown" };

function computeFormatCounts(rows) {
  const counts = new Map();
  rows.forEach((row) => {
    const key = FORMAT_ORDER.includes(row.format) ? row.format : "unknown";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  });
  return [...FORMAT_ORDER, "unknown"]
    .filter((key) => counts.has(key))
    .map((key) => ({
      label: FORMAT_LABELS[key],
      count: counts.get(key),
      color: key === "unknown" ? "var(--text-muted)" : `var(--series-${FORMAT_ORDER.indexOf(key) + 1})`,
    }))
    .sort((a, b) => b.count - a.count);
}

const SIGNED_LABELS = { signed: "signed", unsigned: "unsigned", unknown: "unknown" };
const SIGNED_COLORS = {
  signed: "var(--accent-clean)",
  unsigned: "var(--accent-malicious)",
  unknown: "var(--text-muted)",
};

function computeSignedCounts(rows) {
  const counts = new Map();
  rows.forEach((row) => {
    const key = row.signed === true ? "signed" : row.signed === false ? "unsigned" : "unknown";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  });
  return ["signed", "unsigned", "unknown"]
    .filter((key) => counts.has(key))
    .map((key) => ({ label: SIGNED_LABELS[key], count: counts.get(key), color: SIGNED_COLORS[key] }))
    .sort((a, b) => b.count - a.count);
}

function renderPagination(page, totalPages, totalCount) {
  const pagination = document.getElementById("pagination");
  const status = document.getElementById("pageStatus");
  const prevBtn = document.getElementById("pagePrev");
  const nextBtn = document.getElementById("pageNext");

  pagination.hidden = totalCount === 0 || totalPages <= 1;
  status.textContent = `Page ${page} of ${totalPages} · ${totalCount.toLocaleString("en-US")} packages`;
  prevBtn.disabled = page <= 1;
  nextBtn.disabled = page >= totalPages;
}

function showError(message) {
  const table = document.querySelector(
    "#resultsView:not([hidden]) .table-scroll, #binariesView:not([hidden]) .table-scroll",
  );
  const error = el("p", "error-state", message);
  table.replaceWith(error);
  document.getElementById("statsLine").textContent = "Could not load results.";
}

const CORS_HINT =
  "If you opened index.html by double-clicking it (file://), the browser " +
  "blocks fetch() — serve this directory with a local server instead, e.g. " +
  "`python3 -m http.server` inside site/.";

async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function populateDaySelect(dates, selected) {
  const select = document.getElementById("daySelect");
  select.replaceChildren(
    ...dates.map((date) => {
      const option = el("option", null, dateFmt.format(new Date(`${date}T00:00:00Z`)));
      option.value = date;
      option.selected = date === selected;
      return option;
    }),
  );
}

function initDialog(openId, closeId, dialogId) {
  const openBtn = document.getElementById(openId);
  const closeBtn = document.getElementById(closeId);
  const dialog = document.getElementById(dialogId);
  openBtn.addEventListener("click", () => dialog.showModal());
  closeBtn.addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
}

function initModals() {
  initDialog("glossaryOpen", "glossaryClose", "glossaryDialog");
  initDialog("aboutOpen", "aboutClose", "aboutDialog");
}

initModals();

async function main() {
  let index;
  try {
    index = await fetchJson(INDEX_URL);
  } catch (err) {
    showError(`Could not load data/index.json. ${CORS_HINT}`);
    return;
  }

  if (!index.dates || index.dates.length === 0) {
    showError("No analysis data yet — check back after the next scheduled run.");
    return;
  }

  populateDaySelect(index.dates, index.latest ?? index.dates[0]);

  const daySelect = document.getElementById("daySelect");
  const searchInput = document.getElementById("search");
  const urlOnlyToggle = document.getElementById("urlOnlyToggle");
  const emptyState = document.getElementById("emptyState");

  const facets = Object.fromEntries(FACET_DEFS.map((def) => [def.id, new Set()]));
  const pagePrevBtn = document.getElementById("pagePrev");
  const pageNextBtn = document.getElementById("pageNext");

  const binaryFacets = Object.fromEntries(BINARY_FACET_DEFS.map((def) => [def.id, new Set()]));
  const binariesPagePrevBtn = document.getElementById("binariesPagePrev");
  const binariesPageNextBtn = document.getElementById("binariesPageNext");
  const binariesEmptyState = document.getElementById("binariesEmptyState");
  const binariesOnlyToggle = document.getElementById("binariesOnlyToggle");

  let currentDay = null;
  let currentPage = 1;
  let currentBinariesPage = 1;
  let activeView = "results";

  function refresh({ resetPage = false } = {}) {
    if (!currentDay) return;
    if (resetPage) currentPage = 1;

    const filtered = applyFilters(
      currentDay.packages,
      searchInput.value,
      urlOnlyToggle.checked,
      facets,
    );
    const { page, totalPages, slice } = paginate(filtered, currentPage);
    currentPage = page;

    renderResultsTable(slice);
    renderPagination(page, totalPages, filtered.length);
    emptyState.hidden = filtered.length !== 0;
    FACET_DEFS.forEach((def) => {
      const countEl = document.getElementById(`${def.id}FilterCount`);
      countEl.textContent = facets[def.id].size > 0 ? String(facets[def.id].size) : "";
    });
  }

  function refreshBinaries({ resetPage = false } = {}) {
    if (!currentDay) return;
    if (resetPage) currentBinariesPage = 1;

    const filtered = applyBinaryFilters(
      currentDay.binaries,
      searchInput.value,
      binariesOnlyToggle.checked,
      binaryFacets,
    );
    const { page, totalPages, slice } = paginate(filtered, currentBinariesPage);
    currentBinariesPage = page;

    renderBinariesTable(slice);
    binariesEmptyState.hidden = filtered.length !== 0;

    const pagination = document.getElementById("binariesPagination");
    const status = document.getElementById("binariesPageStatus");
    pagination.hidden = filtered.length === 0 || totalPages <= 1;
    status.textContent = `Page ${page} of ${totalPages} · ${filtered.length.toLocaleString("en-US")} packages`;
    binariesPagePrevBtn.disabled = page <= 1;
    binariesPageNextBtn.disabled = page >= totalPages;
  }

  function renderThreatChart() {
    if (!currentDay) return;
    const entries = computeThreatCounts(currentDay.packages);
    renderBarChart(document.getElementById("threatChart"), entries);
    document.getElementById("threatChartEmpty").hidden = entries.length !== 0;
  }

  function renderVerdictChart() {
    if (!currentDay) return;
    const entries = computeVerdictCounts(currentDay.stats);
    renderBarChart(document.getElementById("verdictChart"), entries);
    document.getElementById("verdictChartEmpty").hidden = entries.length !== 0;
  }

  function renderBinaryCharts() {
    if (!currentDay) return;
    const rows = flattenBinaryRows(currentDay.binaries);

    const formatEntries = computeFormatCounts(rows);
    renderBarChart(document.getElementById("formatChart"), formatEntries);
    document.getElementById("formatChartEmpty").hidden = formatEntries.length !== 0;

    const signedEntries = computeSignedCounts(rows);
    renderBarChart(document.getElementById("signedChart"), signedEntries);
    document.getElementById("signedChartEmpty").hidden = signedEntries.length !== 0;
  }

  function switchView(view) {
    activeView = view;
    document.getElementById("resultsView").hidden = view !== "results";
    document.getElementById("binariesView").hidden = view !== "binaries";
    document.getElementById("chartsView").hidden = view !== "charts";
    document.getElementById("tabResults").setAttribute("aria-selected", String(view === "results"));
    document.getElementById("tabBinaries").setAttribute("aria-selected", String(view === "binaries"));
    document.getElementById("tabCharts").setAttribute("aria-selected", String(view === "charts"));
    searchInput.hidden = view === "charts";
    if (view === "results") refresh();
    else if (view === "binaries") refreshBinaries();
    else if (view === "charts") {
      renderThreatChart();
      renderVerdictChart();
      renderBinaryCharts();
    }
  }

  function jumpToPackage(name) {
    const filtered = applyFilters(
      currentDay.packages,
      searchInput.value,
      urlOnlyToggle.checked,
      facets,
    );
    const index = filtered.findIndex((pkg) => pkg.name === name);
    if (index === -1) return;
    currentPage = Math.floor(index / PAGE_SIZE) + 1;
    refresh();
    const target = document.querySelector(`tr[data-pkg="${cssEscape(name)}"]`);
    if (target) target.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function renderFacetMenus() {
    const options = collectFacetOptions(currentDay.packages);
    FACET_DEFS.forEach((def) => {
      renderFacetMenu(def, options[def.id], facets[def.id], () => refresh({ resetPage: true }));
    });
    const binaryOptions = collectBinaryFacetOptions(flattenBinaryRows(currentDay.binaries));
    BINARY_FACET_DEFS.forEach((def) => {
      renderFacetMenu(def, binaryOptions[def.id], binaryFacets[def.id], () => refreshBinaries({ resetPage: true }));
    });
  }

  async function loadSelectedDay() {
    const date = daySelect.value;
    try {
      currentDay = await fetchJson(dayUrl(date));
    } catch (err) {
      showError(`Could not load data/${date}.json. ${CORS_HINT}`);
      return;
    }
    FACET_DEFS.forEach((def) => facets[def.id].clear());
    BINARY_FACET_DEFS.forEach((def) => binaryFacets[def.id].clear());
    renderStatsLine(currentDay);
    renderSpine(currentDay.packages, jumpToPackage);
    renderFacetMenus();
    refresh({ resetPage: true });
    refreshBinaries({ resetPage: true });
    if (activeView === "charts") {
      renderThreatChart();
      renderVerdictChart();
      renderBinaryCharts();
    }
  }

  daySelect.addEventListener("change", loadSelectedDay);
  searchInput.addEventListener("input", () => {
    if (activeView === "results") refresh({ resetPage: true });
    else refreshBinaries({ resetPage: true });
  });
  urlOnlyToggle.addEventListener("change", () => refresh({ resetPage: true }));
  binariesOnlyToggle.addEventListener("change", () => refreshBinaries({ resetPage: true }));
  pagePrevBtn.addEventListener("click", () => {
    currentPage -= 1;
    refresh();
  });
  pageNextBtn.addEventListener("click", () => {
    currentPage += 1;
    refresh();
  });
  binariesPagePrevBtn.addEventListener("click", () => {
    currentBinariesPage -= 1;
    refreshBinaries();
  });
  binariesPageNextBtn.addEventListener("click", () => {
    currentBinariesPage += 1;
    refreshBinaries();
  });
  document.getElementById("tabResults").addEventListener("click", () => switchView("results"));
  document.getElementById("tabBinaries").addEventListener("click", () => switchView("binaries"));
  document.getElementById("tabCharts").addEventListener("click", () => switchView("charts"));

  const filterDetails = [...FACET_DEFS, ...BINARY_FACET_DEFS].map((def) =>
    document.getElementById(`${def.id}Filter`),
  );
  document.addEventListener("click", (event) => {
    filterDetails.forEach((details) => {
      if (details.open && !details.contains(event.target)) details.open = false;
    });
  });

  await loadSelectedDay();
}

main();
