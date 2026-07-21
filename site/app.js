"use strict";

const PAGE_SIZE = 25;
const INDEX_URL = "data/index.json";
const TRENDS_URL = "data/trends.json";
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

const PY_KEYWORDS = new Set([
  "False", "None", "True", "and", "as", "assert", "async", "await",
  "break", "class", "continue", "def", "del", "elif", "else", "except",
  "finally", "for", "from", "global", "if", "import", "in", "is",
  "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
  "while", "with", "yield",
]);

const PY_RISKY_NAMES = new Set([
  "subprocess", "os", "socket", "urllib", "requests", "shutil",
  "eval", "exec", "compile", "__import__", "getattr", "popen",
  "system", "urlopen", "Popen", "ctypes",
]);

const PY_TOKEN_RE =
  /(?<str>[rRbBfFuU]{0,2}("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'))|(?<num>\b\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?\b)|(?<name>[A-Za-z_][A-Za-z0-9_]*)|(?<space>\s+)|(?<punct>[^\sA-Za-z0-9_'"]+)|(?<other>['"])/g;

/** Tokenize a Python expression string into highlighted DOM spans. */
function highlightPythonCommand(code) {
  const fragment = document.createDocumentFragment();
  PY_TOKEN_RE.lastIndex = 0;
  let match;
  while ((match = PY_TOKEN_RE.exec(code)) !== null) {
    const { str, num, name, space } = match.groups;
    if (space !== undefined) {
      fragment.appendChild(document.createTextNode(space));
      continue;
    }
    const text = match[0];
    let className = "tok-punct";
    if (str !== undefined) className = "tok-str";
    else if (num !== undefined) className = "tok-num";
    else if (name !== undefined) {
      className = PY_KEYWORDS.has(name)
        ? "tok-kw"
        : PY_RISKY_NAMES.has(name)
          ? "tok-risky"
          : "tok-name";
    }
    fragment.appendChild(el("span", className, text));
  }
  return fragment;
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

function urlOpenButton(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;

  const link = el("a", "url-open-btn");
  link.href = parsed.href;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.setAttribute("aria-label", "Open URL");
  link.title = "Open URL";
  link.innerHTML =
    '<svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true">' +
    '<path d="M6.5 9.5 14 2"/><path d="M9.5 2H14v4.5"/>' +
    '<path d="M12 9v3.5A1.5 1.5 0 0 1 10.5 14h-7A1.5 1.5 0 0 1 2 12.5v-7A1.5 1.5 0 0 1 3.5 4H7"/>' +
    "</svg>";
  return link;
}

function urlCell(finding) {
  const cell = el("td", "cell-url");
  const row = el("div", "url-row");
  row.appendChild(el("span", "url-value", finding.url));
  const openBtn = urlOpenButton(finding.url);
  if (openBtn) row.appendChild(openBtn);
  cell.appendChild(row);

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
  if (pkg.version) {
    cell.appendChild(el("span", "pkg-version", pkg.version));
  }
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
  const cell = el("td", "cell-mono");
  const wrapper = el("div", "cell-hash");

  const hashSpan = el("span", "hash-value", `${bin.sha256.slice(0, 12)}…`);
  hashSpan.title = bin.sha256;
  wrapper.appendChild(hashSpan);

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
  wrapper.appendChild(copyBtn);

  wrapper.appendChild(
    inlineLink(
      `https://www.virustotal.com/gui/file/${bin.sha256}`,
      "VT",
      "vt-link",
    ),
  );

  cell.appendChild(wrapper);
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
        const pkgNameCell = el("td", "cell-name");
        pkgNameCell.appendChild(el("span", "pkg-name-value", group.package));
        if (group.version) {
          pkgNameCell.appendChild(el("span", "pkg-version", group.version));
        }
        const encodedGroupVersion = group.version
          ? encodeURIComponent(group.version)
          : null;
        const pypiUrl = encodedGroupVersion
          ? `https://pypi.org/project/${encodeURIComponent(group.package)}/${encodedGroupVersion}/`
          : `https://pypi.org/project/${encodeURIComponent(group.package)}/`;
        const links = el("div", "pkg-links");
        links.appendChild(inlineLink(pypiUrl, "PyPI", "pkg-link"));
        pkgNameCell.appendChild(links);
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

function applyBinaryFilters(binaryGroups, query, facets) {
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
      if (facetsActive && group.binaries.length === 0) return false;
      return true;
    });
}

const INSTALL_HOOK_SOURCE_LABELS = { setup_py: "setup.py", package_init: "__init__.py" };

const INSTALL_HOOK_FACET_DEFS = [
  {
    id: "source",
    field: "source",
    key: (v) => (v ? INSTALL_HOOK_SOURCE_LABELS[v] ?? v : NONE_KEY),
    noneLabel: "Unknown",
  },
  {
    id: "call",
    field: "call",
    key: (v) => (v ? v.split(".")[0] : NONE_KEY),
    noneLabel: "Unknown",
  },
];

function flattenInstallHookRows(installHookGroups) {
  return (installHookGroups ?? []).flatMap((group) =>
    group.install_hooks.map((hook) => ({
      package: group.package,
      analyzed_at: group.analyzed_at,
      ...hook,
    })),
  );
}

function installHookCells(hook, group) {
  const fileText = `${hook.file}:${hook.line}`;
  const distUrl = inspectorDistributionUrl({
    name: group.package,
    version: group.version,
    download_url: group.download_url,
  });
  const file = el("td", "cell-mono cell-file");
  if (distUrl) {
    file.appendChild(
      inlineLink(`${distUrl}${encodeFilePath(hook.file)}`, fileText, "file-link"),
    );
  } else {
    file.appendChild(document.createTextNode(fileText));
  }
  const commandText = hook.command ?? hook.call;
  const commandCell = el("td", "cell-mono cell-command");
  commandCell.title = commandText;
  commandCell.appendChild(highlightPythonCommand(commandText));
  return [
    file,
    el("td", "cell-mono", hook.call),
    commandCell,
    el("td", "cell-mono", hook.context),
    el("td", "cell-mono", INSTALL_HOOK_SOURCE_LABELS[hook.source] ?? hook.source),
  ];
}

function emptyInstallHookCells() {
  return [
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
  ];
}

function renderInstallHooksTable(groups) {
  const tbody = document.getElementById("installHooksBody");
  tbody.replaceChildren();

  groups.forEach((group, groupIndex) => {
    const rowCount = Math.max(group.install_hooks.length, 1);
    const groupClass = groupIndex % 2 === 0 ? "group-a" : "group-b";

    for (let i = 0; i < rowCount; i += 1) {
      const row = el("tr", `result-row ${groupClass}`);

      if (i === 0) {
        const pkgNameCell = el("td", "cell-name");
        pkgNameCell.appendChild(el("span", "pkg-name-value", group.package));
        if (group.version) {
          pkgNameCell.appendChild(el("span", "pkg-version", group.version));
        }
        const encodedGroupVersion = group.version
          ? encodeURIComponent(group.version)
          : null;
        const pypiUrl = encodedGroupVersion
          ? `https://pypi.org/project/${encodeURIComponent(group.package)}/${encodedGroupVersion}/`
          : `https://pypi.org/project/${encodeURIComponent(group.package)}/`;
        const links = el("div", "pkg-links");
        links.appendChild(inlineLink(pypiUrl, "PyPI", "pkg-link"));
        pkgNameCell.appendChild(links);
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
        group.install_hooks.length > 0
          ? installHookCells(group.install_hooks[i], group)
          : emptyInstallHookCells();
      row.append(...cells);
      tbody.appendChild(row);
    }
  });
}

function collectInstallHookFacetOptions(rows) {
  const options = {};
  INSTALL_HOOK_FACET_DEFS.forEach((def) => {
    const counts = new Map();
    rows.forEach((row) => {
      const key = def.key(row[def.field]);
      const label = key === NONE_KEY ? def.noneLabel : key;
      const entry = counts.get(key) ?? { key, label, count: 0 };
      entry.count += 1;
      counts.set(key, entry);
    });
    options[def.id] = [...counts.values()].sort((a, b) => a.label.localeCompare(b.label));
  });
  return options;
}

function installHookMatchesFacets(hook, facets) {
  return INSTALL_HOOK_FACET_DEFS.every((def) => {
    const selected = facets[def.id];
    if (selected.size === 0) return true;
    return selected.has(def.key(hook[def.field]));
  });
}

function applyInstallHookFilters(installHookGroups, query, facets) {
  const needle = query.trim().toLowerCase();
  const facetsActive = INSTALL_HOOK_FACET_DEFS.some((def) => facets[def.id].size > 0);

  return (installHookGroups ?? [])
    .map((group) => {
      if (!facetsActive) return group;
      return {
        ...group,
        install_hooks: group.install_hooks.filter((h) => installHookMatchesFacets(h, facets)),
      };
    })
    .filter((group) => {
      if (needle && !group.package.toLowerCase().includes(needle)) return false;
      if (facetsActive && group.install_hooks.length === 0) return false;
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

function applyFilters(packages, query, facets) {
  const needle = query.trim().toLowerCase();
  const facetsActive = FACET_DEFS.some((def) => facets[def.id].size > 0);

  return packages
    .map((pkg) => {
      if (!facetsActive) return pkg;
      return { ...pkg, findings: pkg.findings.filter((f) => findingMatchesFacets(f, facets)) };
    })
    .filter((pkg) => {
      if (needle && !pkg.name.toLowerCase().includes(needle)) return false;
      if (facetsActive && pkg.findings.length === 0) return false;
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

function renderLineChart(mountEl, points, color) {
  mountEl.replaceChildren();
  if (points.length === 0) return;

  const width = 640;
  const height = 160;
  const padding = { top: 16, right: 12, bottom: 24, left: 12 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const maxValue = Math.max(...points.map((p) => p.value), 1);
  const stepX = points.length > 1 ? plotWidth / (points.length - 1) : 0;
  const svgNs = "http://www.w3.org/2000/svg";

  const coords = points.map((p, i) => ({
    x: padding.left + i * stepX,
    y: padding.top + plotHeight - (p.value / maxValue) * plotHeight,
    ...p,
  }));

  const svg = document.createElementNS(svgNs, "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", String(height));
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Line chart");

  if (coords.length > 1) {
    const path = document.createElementNS(svgNs, "path");
    const d = coords.map((c, i) => `${i === 0 ? "M" : "L"}${c.x},${c.y}`).join(" ");
    path.setAttribute("d", d);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", color);
    path.setAttribute("stroke-width", "2");
    path.setAttribute("stroke-linecap", "round");
    svg.appendChild(path);
  }

  coords.forEach((c) => {
    const dot = document.createElementNS(svgNs, "circle");
    dot.setAttribute("cx", String(c.x));
    dot.setAttribute("cy", String(c.y));
    dot.setAttribute("r", "3");
    dot.setAttribute("fill", color);
    const title = document.createElementNS(svgNs, "title");
    title.textContent = `${c.date}: ${c.value}`;
    dot.appendChild(title);
    svg.appendChild(dot);
  });

  const first = coords[0];
  const last = coords[coords.length - 1];
  const startLabel = document.createElementNS(svgNs, "text");
  startLabel.setAttribute("x", String(first.x));
  startLabel.setAttribute("y", String(height - 4));
  startLabel.setAttribute("class", "chart-label");
  startLabel.textContent = first.date;
  svg.appendChild(startLabel);

  if (last !== first) {
    const endLabel = document.createElementNS(svgNs, "text");
    endLabel.setAttribute("x", String(last.x));
    endLabel.setAttribute("y", String(height - 4));
    endLabel.setAttribute("text-anchor", "end");
    endLabel.setAttribute("class", "chart-label");
    endLabel.textContent = `${last.date} — ${last.value}`;
    svg.appendChild(endLabel);
  }

  mountEl.appendChild(svg);
}

function computeDailySeries(daily, field) {
  return daily.map((d) => ({ date: d.date, value: d[field] }));
}

function computeTopDomainEntries(topDomains) {
  return topDomains.map((entry) => ({
    label: entry.domain,
    count: entry.count,
    color: THREAT_ORDER.includes(entry.threat)
      ? `var(--series-${THREAT_ORDER.indexOf(entry.threat) + 1})`
      : "var(--text-muted)",
  }));
}

function renderRepeatOffendersTable(rows) {
  const tbody = document.getElementById("repeatOffendersBody");
  tbody.replaceChildren();
  rows.forEach((row) => {
    const tr = el("tr", "result-row");
    tr.append(
      el("td", "cell-mono", row.name),
      el("td", "cell-mono", String(row.days_seen)),
      el("td", "cell-mono", String(row.total_findings)),
      el("td", "cell-mono", row.first_seen),
      el("td", "cell-mono", row.last_seen),
    );
    tbody.appendChild(tr);
  });
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

const INSTALL_HOOK_SOURCE_ORDER = ["setup.py", "__init__.py"];
const INSTALL_HOOK_SOURCE_COLORS = { "setup.py": "var(--series-1)", "__init__.py": "var(--series-2)" };

function computeInstallHookSourceCounts(rows) {
  const counts = new Map();
  rows.forEach((row) => {
    const key = INSTALL_HOOK_SOURCE_LABELS[row.source] ?? row.source;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  });
  return INSTALL_HOOK_SOURCE_ORDER.filter((key) => counts.has(key)).map((key) => ({
    label: key,
    count: counts.get(key),
    color: INSTALL_HOOK_SOURCE_COLORS[key],
  }));
}

function computeInstallHookCallCounts(rows) {
  const counts = new Map();
  rows.forEach((row) => {
    const key = row.call.split(".")[0];
    counts.set(key, (counts.get(key) ?? 0) + 1);
  });
  return [...counts.entries()]
    .map(([label, count], index) => ({
      label,
      count,
      color: `var(--series-${(index % 6) + 1})`,
    }))
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
    "#resultsView:not([hidden]) .table-scroll, #binariesView:not([hidden]) .table-scroll, #installHooksView:not([hidden]) .table-scroll",
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

  let trends;
  try {
    trends = await fetchJson(TRENDS_URL);
  } catch (err) {
    trends = { daily: [], top_domains: [], repeat_offenders: [] };
  }

  populateDaySelect(index.dates, index.latest ?? index.dates[0]);

  const daySelect = document.getElementById("daySelect");
  const searchInput = document.getElementById("search");
  const emptyState = document.getElementById("emptyState");

  const facets = Object.fromEntries(FACET_DEFS.map((def) => [def.id, new Set()]));
  const pagePrevBtn = document.getElementById("pagePrev");
  const pageNextBtn = document.getElementById("pageNext");

  const binaryFacets = Object.fromEntries(BINARY_FACET_DEFS.map((def) => [def.id, new Set()]));
  const binariesPagePrevBtn = document.getElementById("binariesPagePrev");
  const binariesPageNextBtn = document.getElementById("binariesPageNext");
  const binariesEmptyState = document.getElementById("binariesEmptyState");

  const installHookFacets = Object.fromEntries(
    INSTALL_HOOK_FACET_DEFS.map((def) => [def.id, new Set()]),
  );
  const installHooksPagePrevBtn = document.getElementById("installHooksPagePrev");
  const installHooksPageNextBtn = document.getElementById("installHooksPageNext");
  const installHooksEmptyState = document.getElementById("installHooksEmptyState");

  let currentDay = null;
  let currentPage = 1;
  let currentBinariesPage = 1;
  let currentInstallHooksPage = 1;
  let activeView = "results";

  function refresh({ resetPage = false } = {}) {
    if (!currentDay) return;
    if (resetPage) currentPage = 1;

    const filtered = applyFilters(currentDay.packages, searchInput.value, facets);
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

    const filtered = applyBinaryFilters(currentDay.binaries, searchInput.value, binaryFacets);
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

  function refreshInstallHooks({ resetPage = false } = {}) {
    if (!currentDay) return;
    if (resetPage) currentInstallHooksPage = 1;

    const filtered = applyInstallHookFilters(
      currentDay.install_hooks,
      searchInput.value,
      installHookFacets,
    );
    const { page, totalPages, slice } = paginate(filtered, currentInstallHooksPage);
    currentInstallHooksPage = page;

    renderInstallHooksTable(slice);
    installHooksEmptyState.hidden = filtered.length !== 0;

    const pagination = document.getElementById("installHooksPagination");
    const status = document.getElementById("installHooksPageStatus");
    pagination.hidden = filtered.length === 0 || totalPages <= 1;
    status.textContent = `Page ${page} of ${totalPages} · ${filtered.length.toLocaleString("en-US")} packages`;
    installHooksPagePrevBtn.disabled = page <= 1;
    installHooksPageNextBtn.disabled = page >= totalPages;
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

  function renderInstallHookCharts() {
    if (!currentDay) return;
    const rows = flattenInstallHookRows(currentDay.install_hooks);

    const sourceEntries = computeInstallHookSourceCounts(rows);
    renderBarChart(document.getElementById("installHookSourceChart"), sourceEntries);
    document.getElementById("installHookSourceChartEmpty").hidden = sourceEntries.length !== 0;

    const callEntries = computeInstallHookCallCounts(rows);
    renderBarChart(document.getElementById("installHookCallChart"), callEntries);
    document.getElementById("installHookCallChartEmpty").hidden = callEntries.length !== 0;
  }

  function renderTrendsView() {
    const findingsSeries = computeDailySeries(trends.daily, "total_findings");
    renderLineChart(document.getElementById("findingsTrendChart"), findingsSeries, "var(--series-1)");
    document.getElementById("findingsTrendEmpty").hidden = findingsSeries.length !== 0;

    const maliciousSeries = computeDailySeries(trends.daily, "malicious_packages");
    renderLineChart(document.getElementById("maliciousTrendChart"), maliciousSeries, "var(--accent-malicious)");
    document.getElementById("maliciousTrendEmpty").hidden = maliciousSeries.length !== 0;

    const domainEntries = computeTopDomainEntries(trends.top_domains);
    renderBarChart(document.getElementById("topDomainsChart"), domainEntries);
    document.getElementById("topDomainsEmpty").hidden = domainEntries.length !== 0;

    renderRepeatOffendersTable(trends.repeat_offenders);
    document.getElementById("repeatOffendersEmpty").hidden = trends.repeat_offenders.length !== 0;
  }

  function switchView(view) {
    activeView = view;
    document.getElementById("resultsView").hidden = view !== "results";
    document.getElementById("binariesView").hidden = view !== "binaries";
    document.getElementById("installHooksView").hidden = view !== "installHooks";
    document.getElementById("chartsView").hidden = view !== "charts";
    document.getElementById("trendsView").hidden = view !== "trends";
    document.getElementById("tabResults").setAttribute("aria-selected", String(view === "results"));
    document.getElementById("tabBinaries").setAttribute("aria-selected", String(view === "binaries"));
    document.getElementById("tabInstallHooks").setAttribute("aria-selected", String(view === "installHooks"));
    document.getElementById("tabCharts").setAttribute("aria-selected", String(view === "charts"));
    document.getElementById("tabTrends").setAttribute("aria-selected", String(view === "trends"));
    searchInput.hidden = view === "charts" || view === "trends";
    daySelect.hidden = view === "trends";
    if (view === "results") refresh();
    else if (view === "binaries") refreshBinaries();
    else if (view === "installHooks") refreshInstallHooks();
    else if (view === "charts") {
      renderThreatChart();
      renderVerdictChart();
      renderBinaryCharts();
      renderInstallHookCharts();
    } else if (view === "trends") {
      renderTrendsView();
    }
  }

  function jumpToPackage(name) {
    const filtered = applyFilters(currentDay.packages, searchInput.value, facets);
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
    const installHookOptions = collectInstallHookFacetOptions(
      flattenInstallHookRows(currentDay.install_hooks),
    );
    INSTALL_HOOK_FACET_DEFS.forEach((def) => {
      renderFacetMenu(def, installHookOptions[def.id], installHookFacets[def.id], () =>
        refreshInstallHooks({ resetPage: true }),
      );
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
    INSTALL_HOOK_FACET_DEFS.forEach((def) => installHookFacets[def.id].clear());
    renderStatsLine(currentDay);
    renderSpine(currentDay.packages, jumpToPackage);
    renderFacetMenus();
    refresh({ resetPage: true });
    refreshBinaries({ resetPage: true });
    refreshInstallHooks({ resetPage: true });
    if (activeView === "charts") {
      renderThreatChart();
      renderVerdictChart();
      renderBinaryCharts();
      renderInstallHookCharts();
    }
  }

  daySelect.addEventListener("change", loadSelectedDay);
  searchInput.addEventListener("input", () => {
    if (activeView === "results") refresh({ resetPage: true });
    else if (activeView === "binaries") refreshBinaries({ resetPage: true });
    else if (activeView === "installHooks") refreshInstallHooks({ resetPage: true });
  });
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
  installHooksPagePrevBtn.addEventListener("click", () => {
    currentInstallHooksPage -= 1;
    refreshInstallHooks();
  });
  installHooksPageNextBtn.addEventListener("click", () => {
    currentInstallHooksPage += 1;
    refreshInstallHooks();
  });
  document.getElementById("tabResults").addEventListener("click", () => switchView("results"));
  document.getElementById("tabBinaries").addEventListener("click", () => switchView("binaries"));
  document.getElementById("tabInstallHooks").addEventListener("click", () => switchView("installHooks"));
  document.getElementById("tabCharts").addEventListener("click", () => switchView("charts"));
  document.getElementById("tabTrends").addEventListener("click", () => switchView("trends"));

  const filterDetails = [...FACET_DEFS, ...BINARY_FACET_DEFS, ...INSTALL_HOOK_FACET_DEFS].map((def) =>
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
