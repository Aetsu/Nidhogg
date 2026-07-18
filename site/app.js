"use strict";

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

function renderSpine(packages) {
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
    mark.addEventListener("click", () => {
      const target = document.querySelector(`tr[data-pkg="${cssEscape(pkg.name)}"]`);
      if (target) target.scrollIntoView({ behavior: "smooth", block: "center" });
    });
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

function showError(message) {
  const table = document.querySelector(".table-scroll");
  const error = el("p", "error-state", message);
  table.replaceWith(error);
  document.getElementById("statsLine").textContent = "Could not load results.";
}

const CORS_HINT =
  "If you opened index.html by double-clicking it (file://), the browser " +
  "blocks fetch() — serve this directory with a local server instead, e.g. " +
  "`python3 -m http.server` inside site/.";

async function fetchJson(url) {
  const response = await fetch(url);
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

  let currentDay = null;

  function refresh() {
    if (!currentDay) return;
    const filtered = applyFilters(
      currentDay.packages,
      searchInput.value,
      urlOnlyToggle.checked,
      facets,
    );
    renderResultsTable(filtered);
    emptyState.hidden = filtered.length !== 0;
    FACET_DEFS.forEach((def) => {
      const countEl = document.getElementById(`${def.id}FilterCount`);
      countEl.textContent = facets[def.id].size > 0 ? String(facets[def.id].size) : "";
    });
  }

  function renderFacetMenus() {
    const options = collectFacetOptions(currentDay.packages);
    FACET_DEFS.forEach((def) => {
      renderFacetMenu(def, options[def.id], facets[def.id], refresh);
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
    renderStatsLine(currentDay);
    renderSpine(currentDay.packages);
    renderFacetMenus();
    refresh();
  }

  daySelect.addEventListener("change", loadSelectedDay);
  searchInput.addEventListener("input", refresh);
  urlOnlyToggle.addEventListener("change", refresh);

  const filterDetails = FACET_DEFS.map((def) => document.getElementById(`${def.id}Filter`));
  document.addEventListener("click", (event) => {
    filterDetails.forEach((details) => {
      if (details.open && !details.contains(event.target)) details.open = false;
    });
  });

  await loadSelectedDay();
}

main();
