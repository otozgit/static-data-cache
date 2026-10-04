/* Atomic v4.2 publisher: public HTTP reads -> validated exact bytes -> one artifact.
 * No deployment/API credentials, database client or legacy fallback in this module.
 */
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  writeFile,
  readFile,
  readdir,
  lstat,
  appendFile,
} from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const FILES = Object.freeze([
  "portal/cache.json",
  "portal/world-status.json",
  "common/identity.json",
  "common/supporter-status.json",
  "products/portal/access.json",
  "world-index.csv",
  "category-index.csv",
  "site-manifest.json",
]);
export const DATA_FILES = Object.freeze(
  FILES.filter((n) => n !== "site-manifest.json"),
);
export const META = Object.freeze([
  "schemaVersion",
  "siteGeneration",
  "generatedAt",
  "portalRevision",
  "commonSupporterRevision",
  "portalSupporterRevision",
  "snapshotVersion",
  "configHash",
]);
export const LIMIT = Object.freeze({
  source: 40000000,
  manifest: 1000000,
  file: 1950000,
  timeout: 30000,
});
export const WORLD_HEADER =
  "WorldID,WorldName,Enabled,ReleaseStatus,RuntimeStatus,LastHttpStatus,Consecutive404,LastSuccessAt,UnavailableSince,InPortalPayload,ReviewSuggested".split(
    ",",
  );
export const CATEGORY_HEADER =
  "SnapshotVersion,SnapshotAt,MainCategoryKey,MainCategoryID,MainState,MainName_EN,MainName_JA,MainName_KO,MainName_ZH_CN,MainName_ZH_TW,SubCategoryKey,CategoryID,SubState,SubName_EN,SubName_JA,SubName_KO,SubName_ZH_CN,SubName_ZH_TW".split(
    ",",
  );
export const ROBOTS = "User-agent: *\nDisallow: /\n";
const HEX = /^[a-f0-9]{64}$/;
const WORLD = /^wrld_[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const PUBLIC_KEY = /^pub_[a-f0-9]{32}$/;
const STATES = ["ACTIVE", "DISABLED_PENDING", "RETIRED"];
export class PublisherError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
const check = (condition, code) => {
  if (!condition) throw new PublisherError(code);
};
const object = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const equal = (a, b) => canonical(a) === canonical(b);
function keys(x, list, code = "KEYS") {
  check(object(x) && equal(Object.keys(x).sort(), [...list].sort()), code);
}
export function canonical(v) {
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (object(v))
    return (
      "{" +
      Object.keys(v)
        .sort()
        .map((k) => JSON.stringify(k) + ":" + canonical(v[k]))
        .join(",") +
      "}"
    );
  return JSON.stringify(v);
}
export const sha256 = (value) =>
  createHash("sha256").update(value).digest("hex");
function utc(s) {
  return (
    typeof s === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(s) &&
    Number.isFinite(Date.parse(s)) &&
    new Date(s).toISOString() === s.replace(/(?<!\.\d{3})Z$/, ".000Z")
  );
}
function metadata(m) {
  check(object(m) && m.schemaVersion === "4.2", "SCHEMA");
  for (const k of ["siteGeneration", "snapshotVersion"])
    check(Number.isSafeInteger(m[k]) && m[k] > 0, "GENERATION");
  for (const k of [
    "portalRevision",
    "commonSupporterRevision",
    "portalSupporterRevision",
  ])
    check(Number.isSafeInteger(m[k]) && m[k] >= 0, "REVISION");
  check(utc(m.generatedAt), "TIME");
  check(
    typeof m.configHash === "string" && HEX.test(m.configHash),
    "CONFIG_HASH",
  );
  check(
    typeof m.bundleHash === "string" && HEX.test(m.bundleHash),
    "BUNDLE_HASH",
  );
}
function jsonObject(raw, canonicalRequired = true) {
  check(typeof raw === "string" && raw.isWellFormed(), "UTF8");
  let v;
  try {
    v = JSON.parse(raw);
  } catch {
    throw new PublisherError("JSON_PARSE");
  }
  check(object(v), "JSON_ROOT");
  if (canonicalRequired) check(canonical(v) === raw, "JSON_CANONICAL");
  return v;
}
export function validateManifest(raw) {
  const m = jsonObject(raw);
  keys(m, [...META, "fileHashes", "bundleHash"], "MANIFEST_KEYS");
  metadata(m);
  keys(m.fileHashes, DATA_FILES, "MANIFEST_FILE_KEYS");
  for (const n of DATA_FILES)
    check(
      typeof m.fileHashes[n] === "string" && HEX.test(m.fileHashes[n]),
      "FILE_HASH_FORMAT",
    );
  const envelope = Object.fromEntries(META.map((k) => [k, m[k]]));
  envelope.fileHashes = m.fileHashes;
  check(sha256(canonical(envelope)) === m.bundleHash, "ENVELOPE_HASH");
  return m;
}
// RFC-style quoted fields. CRLF is mandatory for record boundaries and final record.
// Embedded CR/LF inside quoted values is preserved, matching PortalWorker.csv().
export function parseCsv(raw) {
  check(
    typeof raw === "string" &&
      raw.isWellFormed() &&
      !raw.startsWith("\uFEFF") &&
      raw.endsWith("\r\n"),
    "CSV_END",
  );
  const rows = [];
  let row = [],
    field = "",
    quoted = false,
    closed = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (quoted) {
      if (c === '"') {
        if (raw[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
          closed = true;
        }
      } else field += c;
      continue;
    }
    if (c === ",") {
      row.push(field);
      field = "";
      closed = false;
    } else if (c === "\r") {
      check(raw[++i] === "\n", "CSV_CRLF");
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      closed = false;
    } else if (c === "\n") check(false, "CSV_CRLF");
    else if (c === '"') {
      check(field === "" && !closed, "CSV_QUOTE");
      quoted = true;
    } else {
      check(!closed, "CSV_TRAILING");
      field += c;
    }
  }
  check(!quoted && row.length === 0 && field === "" && !closed, "CSV_UNCLOSED");
  return rows;
}
function uniqueStrings(a, pattern, code) {
  check(
    Array.isArray(a) &&
      a.every((x) => typeof x === "string" && pattern.test(x)) &&
      new Set(a).size === a.length,
    code,
  );
}
function validateCsv(files, source, status, cache) {
  const world = parseCsv(files["world-index.csv"]);
  check(equal(world[0], WORLD_HEADER), "WORLD_HEADER");
  const ids = [];
  for (const r of world.slice(1)) {
    check(r.length === 11 && WORLD.test(r[0]), "WORLD_ROW");
    ids.push(r[0]);
    for (const i of [2, 9, 10])
      check(["true", "false"].includes(r[i]), "WORLD_BOOLEAN");
    check(
      ["", "AVAILABLE", "SUSPECTED_DELETED", "RUNTIME_HIDDEN"].includes(r[4]),
      "WORLD_RUNTIME",
    );
    check(r[5] === "" || /^[1-5]\d{2}$/.test(r[5]), "WORLD_HTTP");
    check(
      /^\d+$/.test(r[6]) && Number.isSafeInteger(Number(r[6])),
      "WORLD_STREAK",
    );
    for (const i of [7, 8]) check(r[i] === "" || utc(r[i]), "WORLD_TIME");
  }
  check(
    new Set(ids).size === ids.length && equal(ids, status.managedWorldIds),
    "WORLD_KEYS",
  );
  check(
    equal(
      world
        .slice(1)
        .filter((r) => r[9] === "true")
        .map((r) => r[0])
        .sort(),
      cache.worlds.map((w) => w.worldId).sort(),
    ),
    "WORLD_VISIBILITY",
  );
  const categories = parseCsv(files["category-index.csv"]);
  check(equal(categories[0], CATEGORY_HEADER), "CATEGORY_HEADER");
  const subs = new Set(),
    mainRows = new Map(),
    mainIds = new Map(),
    subIds = new Set(),
    emptyMains = new Set();
  for (const r of categories.slice(1)) {
    check(
      r.length === 18 &&
        r[0] === String(source.snapshotVersion) &&
        utc(r[1]) &&
        r[1] === cache.snapshotAt,
      "CATEGORY_ROW",
    );
    check(/^MC\d{4,}$/.test(r[2]) && STATES.includes(r[4]), "MAIN_KEY");
    const main = r.slice(2, 10);
    check(
      !mainRows.has(r[2]) || equal(mainRows.get(r[2]), main),
      "MAIN_DUPLICATE",
    );
    mainRows.set(r[2], main);
    // Display IDs may be reused after retirement; permanent keys remain unique.
    if (r[3] && r[4] === "ACTIVE") {
      check(
        !mainIds.has(r[3]) || mainIds.get(r[3]) === r[2],
        "MAIN_ID_DUPLICATE",
      );
      mainIds.set(r[3], r[2]);
    }
    if (!r[10]) {
      check(
        r.slice(11).every((x) => x === "") && !emptyMains.has(r[2]),
        "EMPTY_CATEGORY",
      );
      emptyMains.add(r[2]);
    } else {
      check(
        /^SC\d{4,}$/.test(r[10]) && STATES.includes(r[12]) && !subs.has(r[10]),
        "SUB_KEY",
      );
      subs.add(r[10]);
      if (r[11] && r[12] === "ACTIVE") {
        check(!subIds.has(r[11]), "CATEGORY_ID_DUPLICATE");
        subIds.add(r[11]);
      }
    }
  }
  for (const m of emptyMains)
    check(
      categories.slice(1).filter((r) => r[2] === m).length === 1,
      "EMPTY_MAIN_DUPLICATE",
    );
  check(
    equal(
      [...mainRows.keys()].sort(),
      cache.mainCategories.map((m) => m.mainCategoryKey).sort(),
    ) &&
      equal(
        [...subs].sort(),
        cache.categories.map((c) => c.subCategoryKey).sort(),
      ),
    "CATEGORY_KEYS",
  );
}
function validateLogical(files, source) {
  const parsed = {};
  for (const name of DATA_FILES.filter((n) => n.endsWith(".json"))) {
    const v = jsonObject(files[name]);
    check(v.schemaVersion === "4.2", "LOGICAL_SCHEMA");
    parsed[name] = v;
  }
  const cache = parsed["portal/cache.json"],
    status = parsed["portal/world-status.json"],
    identity = parsed["common/identity.json"],
    common = parsed["common/supporter-status.json"],
    access = parsed["products/portal/access.json"];
  keys(
    cache,
    [
      "averageFavoriteRate",
      "categories",
      "configHash",
      "configuredWorldCount",
      "displayWorldCount",
      "localization",
      "mainCategories",
      "portalRevision",
      "portalSupporterRevision",
      "ranking",
      "schemaVersion",
      "serviceStatus",
      "snapshotAt",
      "snapshotVersion",
      "sortOrders",
      "worlds",
    ],
    "CACHE_KEYS",
  );
  for (const k of [
    "configHash",
    "snapshotVersion",
    "portalRevision",
    "portalSupporterRevision",
  ])
    check(cache[k] === source[k], "CACHE_META");
  check(
    utc(cache.snapshotAt) &&
      ["NORMAL", "MAINTENANCE"].includes(cache.serviceStatus),
    "CACHE_STATE",
  );
  for (const k of ["worlds", "mainCategories", "categories", "localization"])
    check(Array.isArray(cache[k]), "CACHE_ARRAY");
  check(
    Number.isSafeInteger(cache.configuredWorldCount) &&
      cache.configuredWorldCount >= 0 &&
      cache.displayWorldCount === cache.worlds.length,
    "CACHE_COUNT",
  );
  uniqueStrings(
    cache.worlds.map((w) => w.worldId),
    WORLD,
    "CACHE_WORLD_KEYS",
  );
  keys(
    status,
    [
      "schemaVersion",
      "managedWorldIds",
      "disabledWorldIds",
      "unavailableWorldIds",
      "emergencyBlockedWorldIds",
    ],
    "STATUS_KEYS",
  );
  for (const k of [
    "managedWorldIds",
    "disabledWorldIds",
    "unavailableWorldIds",
    "emergencyBlockedWorldIds",
  ]) {
    uniqueStrings(status[k], WORLD, "STATUS_IDS");
    check(equal(status[k], [...status[k]].sort()), "STATUS_ORDER");
  }
  check(
    cache.configuredWorldCount === status.managedWorldIds.length &&
      status.disabledWorldIds.every((id) =>
        status.managedWorldIds.includes(id),
      ),
    "STATUS_MANAGED",
  );
  keys(identity, ["schemaVersion", "identities"], "IDENTITY_KEYS");
  check(object(identity.identities), "IDENTITY_MAP");
  uniqueStrings(
    Object.values(identity.identities),
    PUBLIC_KEY,
    "IDENTITY_PUBLIC_KEYS",
  );
  check(
    Object.keys(identity.identities).every((n) => n.length > 0),
    "IDENTITY_NAMES",
  );
  keys(
    common,
    ["schemaVersion", "commonSupporterRevision", "supporterDataUpdatedAt"],
    "COMMON_KEYS",
  );
  check(
    common.commonSupporterRevision === source.commonSupporterRevision &&
      utc(common.supporterDataUpdatedAt),
    "COMMON_META",
  );
  keys(access, ["schemaVersion", "users"], "ACCESS_KEYS");
  check(object(access.users), "ACCESS_MAP");
  check(
    equal(
      Object.keys(access.users).sort(),
      Object.values(identity.identities).sort(),
    ),
    "ACCESS_IDENTITIES",
  );
  for (const a of Object.values(access.users)) {
    keys(
      a,
      ["profile", "tier", "expiresAt", "canVote", "canSubmit"],
      "ACCESS_ROW",
    );
    check(
      a.profile === "PORTAL_FULL" &&
        ["SUPPORTER", "SPONSOR", "TRIAL"].includes(a.tier) &&
        typeof a.canVote === "boolean" &&
        typeof a.canSubmit === "boolean",
      "ACCESS_STATE",
    );
    if (a.tier === "TRIAL")
      check(
        typeof a.expiresAt === "string" &&
          a.expiresAt.length > 0 &&
          !a.canVote &&
          !a.canSubmit,
        "TRIAL_ACCESS",
      );
    else check(a.expiresAt === null, "ACCESS_EXPIRY");
  }
  keys(cache.ranking, ["date", "entries"], "RANKING_KEYS");
  check(Array.isArray(cache.ranking.entries), "RANKING_ENTRIES");
  for (const e of cache.ranking.entries) {
    keys(
      e,
      ["publicUserKey", "rank", "adoptedCount", "displayName"],
      "RANKING_ROW",
    );
    check(
      PUBLIC_KEY.test(e.publicUserKey) &&
        Number.isSafeInteger(e.rank) &&
        e.rank > 0 &&
        Number.isSafeInteger(e.adoptedCount) &&
        e.adoptedCount >= 0 &&
        typeof e.displayName === "string",
      "RANKING_VALUE",
    );
  }
  validateCsv(files, source, status, cache);
}
export function validateSource(source) {
  keys(source, [...META, "bundleHash", "fileHashes", "files"], "SOURCE_KEYS");
  metadata(source);
  keys(source.files, FILES, "FILE_SET");
  keys(source.fileHashes, FILES, "HASH_SET");
  for (const n of FILES) {
    const raw = source.files[n];
    check(typeof raw === "string" && raw.isWellFormed(), "FILE_STRING");
    check(Buffer.byteLength(raw, "utf8") <= LIMIT.file, "FILE_SIZE");
    check(
      typeof source.fileHashes[n] === "string" &&
        HEX.test(source.fileHashes[n]) &&
        sha256(raw) === source.fileHashes[n],
      "FILE_HASH",
    );
  }
  const manifest = validateManifest(source.files["site-manifest.json"]);
  for (const k of [...META, "bundleHash"])
    check(source[k] === manifest[k], "MANIFEST_META");
  for (const n of DATA_FILES)
    check(source.fileHashes[n] === manifest.fileHashes[n], "MANIFEST_HASH");
  validateLogical(source.files, source);
  return source;
}
export function shouldDeploy(source, published) {
  if (published === null) return true;
  check(published.siteGeneration <= source.siteGeneration, "SOURCE_BEHIND");
  if (published.siteGeneration < source.siteGeneration) return true;
  check(published.bundleHash === source.bundleHash, "GENERATION_CONFLICT");
  return false;
}
export function validateUrl(value, kind) {
  check(
    typeof value === "string" && value.length > 0 && value === value.trim(),
    "URL",
  );
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new PublisherError("URL");
  }
  check(
    u.protocol === "https:" &&
      !u.username &&
      !u.password &&
      !u.search &&
      !u.hash &&
      !/[?#\\\s]/.test(value) &&
      !/%/.test(u.pathname),
    "URL",
  );
  check(
    kind === "source"
      ? u.pathname === "/public-bundle.json"
      : u.pathname.endsWith("/data/v1/site-manifest.json"),
    "URL_PATH",
  );
  return u.href;
}
export async function fetchText(
  url,
  {
    fetchImpl = fetch,
    maxBytes,
    allow404 = false,
    timeoutMs = LIMIT.timeout,
  } = {},
) {
  const controller = new AbortController();
  let timer, reader;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new PublisherError("TIMEOUT"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([
      timeout,
      (async () => {
        const r = await fetchImpl(url, {
          method: "GET",
          redirect: "manual",
          signal: controller.signal,
          headers: { Accept: "application/json", "Cache-Control": "no-cache" },
        });
        if (allow404 && r.status === 404) {
          void r.body?.cancel().catch(() => {});
          return null;
        }
        check(r.status === 200, "HTTP_STATUS");
        const length = r.headers.get("Content-Length");
        if (length !== null)
          check(
            /^\d+$/.test(length) && Number(length) <= maxBytes,
            "RESPONSE_SIZE",
          );
        check(r.body, "EMPTY_RESPONSE");
        reader = r.body.getReader();
        let bytes = 0;
        const chunks = [];
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          bytes += value.byteLength;
          check(bytes <= maxBytes, "RESPONSE_SIZE");
          chunks.push(value);
        }
        try {
          return new TextDecoder("utf-8", {
            fatal: true,
            ignoreBOM: true,
          }).decode(Buffer.concat(chunks));
        } catch {
          throw new PublisherError("UTF8");
        }
      })(),
    ]);
  } catch (e) {
    controller.abort();
    if (reader) void reader.cancel().catch(() => {});
    if (e instanceof PublisherError) throw e;
    throw new PublisherError("FETCH_FAILED");
  } finally {
    clearTimeout(timer);
  }
}
const artifactNames = Object.freeze(
  [...FILES.map((n) => "data/v1/" + n), "robots.txt"].sort(),
);
export async function verifyArtifact(site, source) {
  const found = [],
    dirs = new Set([""]);
  for (const n of artifactNames) {
    let d = path.posix.dirname(n);
    while (d !== ".") {
      dirs.add(d);
      d = path.posix.dirname(d);
    }
  }
  async function walk(base, relative = "") {
    const stat = await lstat(base);
    check(stat.isDirectory() && !stat.isSymbolicLink(), "ARTIFACT_DIRECTORY");
    for (const item of await readdir(base)) {
      const rel = relative ? relative + "/" + item : item,
        p = path.join(base, item),
        s = await lstat(p);
      check(!s.isSymbolicLink(), "ARTIFACT_SYMLINK");
      if (s.isDirectory()) {
        check(dirs.has(rel), "ARTIFACT_EXTRA_DIRECTORY");
        await walk(p, rel);
      } else {
        check(s.isFile() && s.nlink === 1, "ARTIFACT_FILE");
        found.push(rel);
      }
    }
  }
  await walk(site);
  check(equal(found.sort(), artifactNames), "ARTIFACT_FILES");
  for (const n of FILES) {
    const bytes = await readFile(path.join(site, "data", "v1", n));
    check(
      bytes.length <= LIMIT.file &&
        sha256(bytes) === source.fileHashes[n] &&
        bytes.equals(Buffer.from(source.files[n], "utf8")),
      "ARTIFACT_BYTES",
    );
  }
  check(
    (await readFile(path.join(site, "robots.txt"), "utf8")) === ROBOTS,
    "ROBOTS",
  );
}
export async function buildArtifact(source, tempRoot) {
  validateSource(source);
  check(typeof tempRoot === "string" && tempRoot.length > 0, "TEMP_ROOT");
  const base = await lstat(tempRoot);
  check(base.isDirectory() && !base.isSymbolicLink(), "TEMP_ROOT");
  const folder = await mkdtemp(
      path.join(path.resolve(tempRoot), "publisher-v42-"),
    ),
    site = path.join(folder, "site");
  await mkdir(site);
  for (const n of FILES) {
    const target = path.join(site, "data", "v1", n);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, Buffer.from(source.files[n], "utf8"), {
      flag: "wx",
    });
  }
  await writeFile(path.join(site, "robots.txt"), ROBOTS, { flag: "wx" });
  await verifyArtifact(site, source);
  return site;
}
export async function prepare({
  sourceUrl,
  publishedUrl,
  tempRoot,
  fetchImpl = fetch,
  timeoutMs = LIMIT.timeout,
}) {
  const sourceEndpoint = validateUrl(sourceUrl, "source"),
    publishedEndpoint = validateUrl(publishedUrl, "published");
  const raw = await fetchText(sourceEndpoint, {
    fetchImpl,
    maxBytes: LIMIT.source,
    timeoutMs,
  });
  const source = validateSource(jsonObject(raw, false));
  const previous = await fetchText(publishedEndpoint, {
    fetchImpl,
    maxBytes: LIMIT.manifest,
    allow404: true,
    timeoutMs,
  });
  const published = previous === null ? null : validateManifest(previous);
  const deploy = shouldDeploy(source, published),
    result = {
      should_deploy: deploy,
      site_generation: source.siteGeneration,
      bundle_hash: source.bundleHash,
    };
  if (deploy) result.artifact_path = await buildArtifact(source, tempRoot);
  return result;
}
async function cli() {
  try {
    const result = await prepare({
      sourceUrl: process.env.SOURCE_URL,
      publishedUrl: process.env.PUBLISHED_MANIFEST_URL,
      tempRoot: process.env.RUNNER_TEMP,
    });
    check(
      typeof process.env.GITHUB_OUTPUT === "string" &&
        process.env.GITHUB_OUTPUT.length > 0,
      "OUTPUT_PATH",
    );
    for (const [k, v] of Object.entries(result)) {
      check(!/[\r\n]/.test(String(v)), "OUTPUT_VALUE");
      await appendFile(process.env.GITHUB_OUTPUT, `${k}=${v}\n`);
    }
    console.log(
      JSON.stringify({
        should_deploy: result.should_deploy,
        site_generation: result.site_generation,
        bundle_hash: result.bundle_hash,
        file_count: FILES.length,
      }),
    );
  } catch (e) {
    console.error(e instanceof PublisherError ? e.code : "PUBLISHER_FAILED");
    process.exitCode = 1;
  }
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
)
  await cli();
