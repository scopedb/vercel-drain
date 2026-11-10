/*
 * Copyright 2026 ScopeDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Client } from "scopedb";

export interface Env {
  SCOPEDB_ENDPOINT: string;
  SCOPEDB_API_KEY: string;
  VERCEL_DRAIN_SECRET?: string;
  DRAIN_AUTH_TOKEN?: string;
  VERCEL_VERIFY_TOKEN?: string;
  SCOPEDB_DATABASE?: string;
  SCOPEDB_SCHEMA?: string;
  SCOPEDB_TABLE?: string;
}

export type VercelEventType =
  | "vercel.request"
  | "vercel.log"
  | "vercel.pageview"
  | "vercel.custom_event"
  | "vercel.web_vital";

export interface VercelEventRow extends Record<string, unknown> {
  event_id: string;
  occurred_at: string;
  service: string;
  event_type: VercelEventType;
  outcome: "ok" | "client_error" | "error";
  level: "debug" | "info" | "warn" | "error";
  method: string | null;
  host: string | null;
  path: string | null;
  status: number | null;
  request_id: string | null;
  message: string;
  attributes: Record<string, unknown>;
}

export interface UrlCaptureOptions {
  /** Capture only these query keys. By default all keys are captured; [] disables query capture. */
  readonly allowedQueryParams?: readonly string[];
  /** Applied to each decoded query value. Return null to omit that value. */
  readonly redactQueryValue?: (key: string, value: string) => string | null;
  /** Applied to request and Referer pathnames before token redaction. Return null to omit a path. */
  readonly redactPath?: (pathname: string, hostname: string) => string | null;
}

export interface VercelDrainOptions extends UrlCaptureOptions {
  readonly fetch?: typeof globalThis.fetch;
  readonly shouldRecord?: (row: VercelEventRow, rawItem: Readonly<Record<string, unknown>>) => boolean;
}

const DEFAULT_DATABASE = "scopedb";
const DEFAULT_SCHEMA = "public";
const DEFAULT_TABLE = "vercel_events";

const MAX_BODY_BYTES = 10 * 1024 * 1024;
const MAX_SANITIZE_DEPTH = 8;
const MAX_USER_AGENT_LENGTH = 512;
const MAX_MESSAGE_LENGTH = 2048;
const MAX_STACK_LENGTH = 8192;
const MAX_PATH_LENGTH = 2048;
const MIN_INT64 = BigInt("-9223372036854775808");
const MAX_INT64 = BigInt("9223372036854775807");

const TRACEPARENT_PATTERN = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/i;
const HEX_SIGNATURE_PATTERN = /^[0-9a-f]{40}$/i;

export function createVercelDrainHandler(options: VercelDrainOptions = {}) {
  return {
    async fetch(request: Request, runtimeEnv?: Partial<Env>): Promise<Response> {
      const env = resolveEnv(runtimeEnv);
      const verifyToken = nonEmptyString(env.VERCEL_VERIFY_TOKEN);
      const verifyHeader = verifyToken !== null ? { "x-vercel-verify": verifyToken } : undefined;

      if (request.method === "GET" || request.method === "HEAD") {
        return new Response(null, {
          status: 200,
          ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}),
        });
      }

      if (request.method !== "POST") {
        return Response.json(
          { error: "Method Not Allowed" },
          { status: 405, headers: { Allow: "GET, HEAD, POST", ...(verifyHeader ?? {}) } },
        );
      }

      let endpoint: string;
      let apiKey: string;
      try {
        endpoint = requiredBinding(env.SCOPEDB_ENDPOINT, "SCOPEDB_ENDPOINT");
        apiKey = requiredBinding(env.SCOPEDB_API_KEY, "SCOPEDB_API_KEY");
      } catch (err) {
        return Response.json(
          { error: err instanceof Error ? err.message : "Missing configuration" },
          { status: 500, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
        );
      }

      const drainSecret = nonEmptyString(env.VERCEL_DRAIN_SECRET);
      const bearerToken = nonEmptyString(env.DRAIN_AUTH_TOKEN);
      if (drainSecret === null && bearerToken === null) {
        return Response.json(
          { error: "Missing Drain authentication configuration: set VERCEL_DRAIN_SECRET or DRAIN_AUTH_TOKEN" },
          { status: 500, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
        );
      }

      let rawBody: Uint8Array;
      try {
        rawBody = await readRequestBody(request, MAX_BODY_BYTES);
      } catch (err) {
        if (err instanceof PayloadTooLargeError) {
          return Response.json(
            { error: "Payload Too Large" },
            { status: 413, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
          );
        }
        return Response.json(
          { error: "Invalid request body" },
          { status: 400, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
        );
      }

      // When Vercel verifies a new Drain endpoint via an empty POST probe before sending signed batches,
      // acknowledge with x-vercel-verify if configured.
      if (rawBody.byteLength === 0 && verifyToken !== null) {
        return new Response(null, { status: 200, headers: { "x-vercel-verify": verifyToken } });
      }

      const authenticated = await verifyDrainRequest(request.headers, rawBody, drainSecret, bearerToken);
      if (!authenticated) {
        return Response.json(
          { error: "Unauthorized" },
          { status: 401, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
        );
      }

      let decodedText: string;
      try {
        const decompressed = await maybeDecompressGzip(rawBody, request.headers.get("content-encoding"), MAX_BODY_BYTES);
        decodedText = new TextDecoder("utf-8", { fatal: false }).decode(decompressed);
      } catch (err) {
        if (err instanceof PayloadTooLargeError) {
          return Response.json(
            { error: "Payload Too Large" },
            { status: 413, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
          );
        }
        return Response.json(
          { error: "Invalid content encoding" },
          { status: 400, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
        );
      }

      let items: Record<string, unknown>[];
      try {
        items = parseDrainPayload(decodedText);
      } catch {
        return Response.json(
          { error: "Malformed JSON or NDJSON payload" },
          { status: 400, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
        );
      }

      const rows: VercelEventRow[] = [];
      for (const item of items) {
        for (const row of drainItemToRows(item, options)) {
          if (options.shouldRecord === undefined || options.shouldRecord(row, item)) {
            rows.push(row);
          }
        }
      }

      if (rows.length === 0) {
        return Response.json(
          { num_rows_inserted: 0 },
          { status: 200, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
        );
      }

      const database = nonEmptyString(env.SCOPEDB_DATABASE) ?? DEFAULT_DATABASE;
      const schema = nonEmptyString(env.SCOPEDB_SCHEMA) ?? DEFAULT_SCHEMA;
      const table = nonEmptyString(env.SCOPEDB_TABLE) ?? DEFAULT_TABLE;

      const client = new Client(endpoint, {
        apiKey,
        ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
      });
      const stream = client
        .table(table, { database, schema })
        .appendStream()
        .strictEncoding(true)
        .maxConcurrentBatches(1)
        .attemptTimeoutMs(10_000)
        .maxElapsedTimeMs(25_000)
        .maxRetries(2)
        .build();

      try {
        await stream.sendAll(rows);
      } finally {
        await stream.shutdown();
      }

      return Response.json(
        { num_rows_inserted: rows.length },
        { status: 200, ...(verifyHeader !== undefined ? { headers: verifyHeader } : {}) },
      );
    },
  };
}

export function createNextRouteHandler(options: VercelDrainOptions = {}) {
  const handler = createVercelDrainHandler(options);
  return (request: Request): Promise<Response> => handler.fetch(request);
}

export default createVercelDrainHandler();

export async function verifyVercelSignature(
  rawBody: Uint8Array,
  signatureHex: string | null,
  secret: string,
): Promise<boolean> {
  if (signatureHex === null) {
    return false;
  }
  const normalizedHex = signatureHex.trim().replace(/^sha1=/i, "");
  if (!HEX_SIGNATURE_PATTERN.test(normalizedHex)) {
    return false;
  }
  const signatureBytes = hexToBytes(normalizedHex);
  const secretBytes = new TextEncoder().encode(secret);
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify("HMAC", key, new Uint8Array(signatureBytes), new Uint8Array(rawBody));
}

export function parseDrainPayload(rawText: string): Record<string, unknown>[] {
  const trimmed = rawText.trim();
  if (trimmed.length === 0) {
    return [];
  }
  if (trimmed.startsWith("[")) {
    const parsed: unknown = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) {
      throw new Error("Expected JSON array");
    }
    return parsed.filter(isPlainObject);
  }
  const lines = trimmed.split(/\r?\n/);
  const items: Record<string, unknown>[] = [];
  for (const line of lines) {
    const clean = line.trim();
    if (clean.length === 0) {
      continue;
    }
    const parsed: unknown = JSON.parse(clean);
    if (Array.isArray(parsed)) {
      for (const element of parsed) {
        if (isPlainObject(element)) {
          items.push(element);
        }
      }
    } else if (isPlainObject(parsed)) {
      items.push(parsed);
    } else {
      throw new Error("Expected JSON object line");
    }
  }
  return items;
}

export function drainItemsToRows(
  items: readonly Readonly<Record<string, unknown>>[],
  options: UrlCaptureOptions = {},
): VercelEventRow[] {
  return items.flatMap((item) => drainItemToRows(item, options));
}

export function drainItemToRows(
  item: Readonly<Record<string, unknown>>,
  options: UrlCaptureOptions = {},
): VercelEventRow[] {
  const schema = stringField(item["schema"]);
  if (schema?.startsWith("vercel.analytics.") === true || (item["eventType"] === "pageview" || item["eventType"] === "event")) {
    return [analyticsItemToRow(item, options)];
  }
  if (schema?.startsWith("vercel.speed_insights.") === true || typeof item["metricType"] === "string") {
    return [speedInsightsItemToRow(item, options)];
  }
  return logDrainItemToRows(item, options);
}

function logDrainItemToRows(
  item: Readonly<Record<string, unknown>>,
  options: UrlCaptureOptions,
): VercelEventRow[] {
  const proxy = isPlainObject(item["proxy"]) ? item["proxy"] : undefined;
  const occurredAt = formatTimestamp(item["timestamp"] ?? proxy?.["timestamp"]);
  const service =
    nonEmptyString(item["projectName"]) ??
    nonEmptyString(item["projectId"]) ??
    nonEmptyString(item["deploymentId"]) ??
    "unknown";

  const method = nonEmptyString(proxy?.["method"]) ?? nonEmptyString(item["method"]);
  const rawHost = nonEmptyString(proxy?.["host"]) ?? nonEmptyString(item["host"]);
  const rawPath = nonEmptyString(proxy?.["path"]) ?? nonEmptyString(item["path"]);
  const parsedTarget = extractUrlOrPathMetadata(rawHost, rawPath, undefined, options, true);
  const referer = extractUrlMetadata(
    nonEmptyString(proxy?.["referer"]) ?? nonEmptyString(item["referer"]) ?? undefined,
    options,
    false,
  );
  const status = safeHttpStatus(proxy?.["statusCode"] ?? item["statusCode"]);
  const requestId = nonEmptyString(item["requestId"]) ?? nonEmptyString(item["id"]);
  const rawMessage = nonEmptyString(item["message"]);
  const rawLevel = nonEmptyString(item["level"]);
  const source = nonEmptyString(item["source"]) ?? "unknown";
  const traceFromHeader = extractTraceContext(
    nonEmptyString(item["traceparent"]) ?? undefined,
  );
  const traceId = nonEmptyString(item["traceId"]) ?? traceFromHeader.traceId;
  const spanId = nonEmptyString(item["spanId"]) ?? traceFromHeader.spanId;
  const userAgent = extractUserAgent(proxy?.["userAgent"] ?? item["userAgent"]);

  const isHttpRequest = proxy !== undefined || method !== null || status !== null;
  const baseAttributes: Record<string, unknown> = {
    project_id: nonEmptyString(item["projectId"]),
    deployment_id: nonEmptyString(item["deploymentId"]),
    environment: nonEmptyString(item["environment"]),
    branch: nonEmptyString(item["branch"]),
    source,
    entrypoint: nonEmptyString(item["entrypoint"]),
    route: nonEmptyString(item["route"]) ?? nonEmptyString(item["entrypoint"]),
    region: nonEmptyString(proxy?.["region"]),
    execution_region: nonEmptyString(item["executionRegion"]),
    edge_type: nonEmptyString(item["edgeType"]),
    vercel_cache: nonEmptyString(proxy?.["vercelCache"]),
    cache_id: nonEmptyString(proxy?.["cacheId"]),
    wap_action: nonEmptyString(proxy?.["wafAction"]),
    duration_ms: finiteNumber(item["duration"] ?? item["durationMs"]),
    trace_id: traceId,
    span_id: spanId,
    user_agent: userAgent,
    referer_host: referer.host,
    referer_path: referer.path,
    query: parsedTarget.query,
  };

  const rows: VercelEventRow[] = [];

  if (isHttpRequest) {
    const outcome = httpOutcome(status, rawLevel);
    const level = httpLevel(status, rawLevel);
    rows.push({
      event_id: nonEmptyString(item["id"]) ?? crypto.randomUUID(),
      occurred_at: occurredAt,
      service,
      event_type: "vercel.request",
      outcome,
      level,
      method,
      host: parsedTarget.host,
      path: parsedTarget.path,
      status,
      request_id: requestId,
      message: formatRequestMessage(method, parsedTarget.path, status, rawMessage),
      attributes: baseAttributes,
    });
  }

  if (!isHttpRequest || (rawMessage !== null && source !== "static" && source !== "external")) {
    const level = normalizeLogLevel(rawLevel);
    const outcome = level === "error" ? "error" : "ok";
    rows.push({
      event_id: isHttpRequest ? crypto.randomUUID() : (nonEmptyString(item["id"]) ?? crypto.randomUUID()),
      occurred_at: occurredAt,
      service,
      event_type: "vercel.log",
      outcome,
      level,
      method,
      host: parsedTarget.host,
      path: parsedTarget.path,
      status,
      request_id: requestId,
      message: boundedString(rawMessage, MAX_MESSAGE_LENGTH) ?? `${source} log`,
      attributes: {
        ...baseAttributes,
        raw_level: rawLevel,
      },
    });
  }

  return rows;
}

function analyticsItemToRow(
  item: Readonly<Record<string, unknown>>,
  options: UrlCaptureOptions,
): VercelEventRow {
  const occurredAt = formatTimestamp(item["timestamp"]);
  const service =
    nonEmptyString(item["projectName"]) ??
    nonEmptyString(item["DataSourceName"]) ??
    nonEmptyString(item["projectId"]) ??
    "unknown";
  const isCustomEvent = item["eventType"] === "event";
  const eventType: VercelEventType = isCustomEvent ? "vercel.custom_event" : "vercel.pageview";
  const eventName = nonEmptyString(item["eventName"]);

  const origin = nonEmptyString(item["origin"]) ?? nonEmptyString(item["vercelUrl"]);
  const rawPath = nonEmptyString(item["path"]);
  const rawQueryParams = nonEmptyString(item["queryParams"]);
  const parsedTarget = extractUrlOrPathMetadata(origin, rawPath, rawQueryParams ?? undefined, options, true);
  const referer = extractUrlMetadata(nonEmptyString(item["referrer"]) ?? undefined, options, false);

  return {
    event_id: crypto.randomUUID(),
    occurred_at: occurredAt,
    service,
    event_type: eventType,
    outcome: "ok",
    level: "info",
    method: "GET",
    host: parsedTarget.host,
    path: parsedTarget.path,
    status: 200,
    request_id: nonEmptyString(item["sessionId"] !== undefined ? String(item["sessionId"]) : null),
    message: isCustomEvent
      ? `event ${eventName ?? "custom"} on ${parsedTarget.path ?? "/"}`
      : `pageview ${parsedTarget.path ?? "/"}`,
    attributes: {
      schema: nonEmptyString(item["schema"]) ?? "vercel.analytics.v2",
      project_id: nonEmptyString(item["projectId"]),
      deployment_id: nonEmptyString(item["deployment"]),
      environment: nonEmptyString(item["vercelEnvironment"]),
      route: nonEmptyString(item["route"]),
      event_name: eventName,
      event_data: item["eventData"] !== undefined ? sanitizeValue(item["eventData"], 0, new Set()) : null,
      country: nonEmptyString(item["country"]),
      region: nonEmptyString(item["region"]),
      city: nonEmptyString(item["city"]),
      device_type: nonEmptyString(item["deviceType"]),
      os_name: nonEmptyString(item["osName"]),
      os_version: nonEmptyString(item["osVersion"]),
      client_name: nonEmptyString(item["clientName"]),
      client_version: nonEmptyString(item["clientVersion"]),
      referer_host: referer.host,
      referer_path: referer.path,
      query: parsedTarget.query,
    },
  };
}

function speedInsightsItemToRow(
  item: Readonly<Record<string, unknown>>,
  options: UrlCaptureOptions,
): VercelEventRow {
  const occurredAt = formatTimestamp(item["timestamp"]);
  const service =
    nonEmptyString(item["projectName"]) ??
    nonEmptyString(item["projectId"]) ??
    "unknown";
  const origin = nonEmptyString(item["origin"]) ?? nonEmptyString(item["vercelUrl"]);
  const rawPath = nonEmptyString(item["path"]);
  const parsedTarget = extractUrlOrPathMetadata(origin, rawPath, undefined, options, false);
  const metricType = nonEmptyString(item["metricType"]) ?? "WEB_VITAL";
  const metricValue = finiteNumber(item["value"]);
  const rating = nonEmptyString(item["rating"]);

  return {
    event_id: crypto.randomUUID(),
    occurred_at: occurredAt,
    service,
    event_type: "vercel.web_vital",
    outcome: rating === "poor" ? "client_error" : "ok",
    level: rating === "poor" ? "warn" : "info",
    method: "GET",
    host: parsedTarget.host,
    path: parsedTarget.path,
    status: null,
    request_id: nonEmptyString(item["id"]),
    message: metricValue !== null ? `${metricType} ${metricValue} (${rating ?? "unrated"})` : metricType,
    attributes: {
      schema: nonEmptyString(item["schema"]) ?? "vercel.speed_insights.v1",
      project_id: nonEmptyString(item["projectId"]),
      deployment_id: nonEmptyString(item["deployment"]),
      environment: nonEmptyString(item["vercelEnvironment"]),
      route: nonEmptyString(item["route"]),
      metric_type: metricType,
      metric_value: metricValue,
      rating,
      country: nonEmptyString(item["country"]),
      region: nonEmptyString(item["region"]),
      city: nonEmptyString(item["city"]),
      device_type: nonEmptyString(item["deviceType"]),
      os_name: nonEmptyString(item["osName"]),
      client_name: nonEmptyString(item["clientName"]),
    },
  };
}

function extractUrlOrPathMetadata(
  rawHostOrOrigin: string | null,
  rawPathOrUrl: string | null,
  rawQueryString: string | undefined,
  options: UrlCaptureOptions,
  captureQuery = true,
): {
  host: string | null;
  path: string | null;
  query: Record<string, string[]>;
} {
  let candidateUrl: string | undefined;
  let hasExplicitHost = rawHostOrOrigin !== null;
  if (rawPathOrUrl !== null && /^https?:\/\//i.test(rawPathOrUrl)) {
    candidateUrl = rawPathOrUrl;
    hasExplicitHost = true;
  } else {
    const baseOrigin =
      rawHostOrOrigin !== null
        ? /^https?:\/\//i.test(rawHostOrOrigin)
          ? rawHostOrOrigin
          : `https://${rawHostOrOrigin}`
        : "https://placeholder.local";
    const normalizedPath =
      rawPathOrUrl !== null ? (rawPathOrUrl.startsWith("/") ? rawPathOrUrl : `/${rawPathOrUrl}`) : "/";
    const querySuffix =
      rawQueryString !== undefined && rawQueryString.length > 0
        ? rawQueryString.startsWith("?")
          ? rawQueryString
          : `?${rawQueryString}`
        : "";
    candidateUrl = `${baseOrigin}${normalizedPath}${querySuffix}`;
  }
  const extracted = extractUrlMetadata(candidateUrl, options, captureQuery, hasExplicitHost);
  return {
    host: hasExplicitHost ? extracted.host : null,
    path: rawPathOrUrl === null ? null : extracted.path,
    query: extracted.query,
  };
}

function extractUrlMetadata(
  rawUrl: string | undefined,
  options: UrlCaptureOptions,
  captureQuery = true,
  hasExplicitHost = true,
): {
  host: string | null;
  path: string | null;
  query: Record<string, string[]>;
} {
  const empty = { host: null, path: null, query: {} };
  if (!rawUrl) return empty;
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return empty;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return empty;

  const effectiveHostname = hasExplicitHost ? parsed.hostname : "";
  const pathname = options.redactPath ? options.redactPath(parsed.pathname, effectiveHostname) : parsed.pathname;
  const path = pathname === null ? null : boundedString(pathname.split("/").map((segment) => {
    try {
      // Inspect decoded data before truncation, including Referer paths and raw Vercel Log Drain paths.
      const decoded = decodeURIComponent(segment);
      return redactTokens(decoded) === decoded ? segment : "REDACTED";
    } catch {
      return "REDACTED";
    }
  }).join("/"), MAX_PATH_LENGTH);

  if (!captureQuery) return { host: parsed.hostname, path, query: {} };
  const allowed = options.allowedQueryParams === undefined ? null : new Set(options.allowedQueryParams);
  const query = new Map<string, string[]>();
  for (const [key, value] of parsed.searchParams) {
    if (allowed !== null && !allowed.has(key)) continue;
    const captured = options.redactQueryValue ? options.redactQueryValue(key, value) : value;
    if (captured === null) continue;
    const values = query.get(key) ?? [];
    values.push(captured);
    query.set(key, values);
  }
  return { host: parsed.hostname, path, query: Object.fromEntries(query) };
}

// Defense in depth only: short secrets and personal data require an application capture policy.
function redactTokens(value: string): string {
  return value.replace(/[a-zA-Z0-9+_-]+/g, (token) => {
    // Prefixes such as tok_ can hide an otherwise recognizable hex identifier.
    return isSensitiveToken(token)
      || isSensitiveToken(token.replace(/^[a-zA-Z]+[_-]/, ""))
      || token.split(/[_-]/).some(isSensitiveToken) ? "REDACTED" : token;
  });
}

function isSensitiveToken(token: string): boolean {
  const compact = token.replace(/[+_-]/g, "");
  if (/^[a-fA-F0-9]{32,}$/.test(compact)) return true;
  if (token.length >= 21 && (token.match(/[A-Z]/g)?.length ?? 0) >= 2
    && (token.match(/[a-z]/g)?.length ?? 0) >= 2 && (token.match(/[0-9]/g)?.length ?? 0) >= 2) return true;
  if (!/^\d{13,19}$/.test(compact)) return false;
  let sum = 0;
  for (let i = compact.length - 1; i >= 0; i--) {
    let digit = Number(compact[i]);
    if ((compact.length - 1 - i) % 2 === 1) digit *= 2;
    sum += digit > 9 ? digit - 9 : digit;
  }
  return sum % 10 === 0;
}

function extractTraceContext(traceparent: string | undefined): {
  traceId: string | null;
  spanId: string | null;
} {
  if (traceparent === undefined) {
    return { traceId: null, spanId: null };
  }
  const match = TRACEPARENT_PATTERN.exec(traceparent.trim());
  const traceId = match?.[1]?.toLowerCase() ?? null;
  const spanId = match?.[2]?.toLowerCase() ?? null;
  if (traceId === null || traceId === "00000000000000000000000000000000") {
    return { traceId: null, spanId: null };
  }
  return { traceId, spanId };
}

function extractUserAgent(raw: unknown): string | null {
  if (typeof raw === "string") {
    return boundedString(nonEmptyString(raw), MAX_USER_AGENT_LENGTH);
  }
  if (Array.isArray(raw)) {
    const joined = raw.filter((item): item is string => typeof item === "string" && item.trim().length > 0).join(" ");
    return boundedString(nonEmptyString(joined), MAX_USER_AGENT_LENGTH);
  }
  return null;
}

function httpOutcome(status: number | null, rawLevel: string | null): "ok" | "client_error" | "error" {
  if ((status !== null && status >= 500) || rawLevel === "error" || rawLevel === "fatal") {
    return "error";
  }
  if (status !== null && status >= 400) {
    return "client_error";
  }
  return "ok";
}

function httpLevel(status: number | null, rawLevel: string | null): "info" | "warn" | "error" {
  if ((status !== null && status >= 500) || rawLevel === "error" || rawLevel === "fatal") {
    return "error";
  }
  if ((status !== null && status >= 400) || rawLevel === "warn" || rawLevel === "warning") {
    return "warn";
  }
  return "info";
}

function normalizeLogLevel(level: string | null): "debug" | "info" | "warn" | "error" {
  const lower = level?.toLowerCase() ?? "info";
  if (lower === "error" || lower === "fatal") {
    return "error";
  }
  if (lower === "warn" || lower === "warning") {
    return "warn";
  }
  if (lower === "debug" || lower === "trace") {
    return "debug";
  }
  return "info";
}

function formatRequestMessage(
  method: string | null,
  path: string | null,
  status: number | null,
  fallbackMessage: string | null,
): string {
  if (method !== null && path !== null) {
    return status !== null ? `${method} ${path} -> ${status}` : `${method} ${path}`;
  }
  if (path !== null) {
    return status !== null ? `${path} -> ${status}` : path;
  }
  return boundedString(fallbackMessage, MAX_MESSAGE_LENGTH) ?? "request";
}

function formatTimestamp(epochMs: unknown): string {
  if (typeof epochMs === "number" && Number.isFinite(epochMs)) {
    const date = new Date(epochMs);
    if (Number.isFinite(date.getTime())) {
      return date.toISOString();
    }
  }
  if (typeof epochMs === "string" && epochMs.trim().length > 0) {
    const parsed = new Date(epochMs);
    if (Number.isFinite(parsed.getTime())) {
      return parsed.toISOString();
    }
  }
  return new Date().toISOString();
}

async function verifyDrainRequest(
  headers: Headers,
  rawBody: Uint8Array,
  drainSecret: string | null,
  bearerToken: string | null,
): Promise<boolean> {
  if (drainSecret !== null) {
    const signature = headers.get("x-vercel-signature") ?? headers.get("x-zeit-signature");
    if (await verifyVercelSignature(rawBody, signature, drainSecret)) {
      return true;
    }
  }
  if (bearerToken !== null) {
    const authHeader = headers.get("authorization");
    if (authHeader !== null && authHeader.startsWith("Bearer ")) {
      const provided = authHeader.slice("Bearer ".length).trim();
      if (constantTimeEqualStrings(provided, bearerToken)) {
        return true;
      }
    }
  }
  return false;
}

function constantTimeEqualStrings(a: string, b: string): boolean {
  const bytesA = new TextEncoder().encode(a);
  const bytesB = new TextEncoder().encode(b);
  if (bytesA.byteLength !== bytesB.byteLength) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < bytesA.byteLength; i++) {
    diff |= (bytesA[i] ?? 0) ^ (bytesB[i] ?? 0);
  }
  return diff === 0;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

class PayloadTooLargeError extends Error {}

async function readRequestBody(request: Request, maxBytes: number): Promise<Uint8Array> {
  if (request.body === null) {
    return new Uint8Array(0);
  }
  return readStreamBounded(request.body, maxBytes);
}

async function maybeDecompressGzip(
  rawBody: Uint8Array,
  contentEncoding: string | null,
  maxBytes: number,
): Promise<Uint8Array> {
  if (contentEncoding === null || contentEncoding.toLowerCase().trim() !== "gzip") {
    return rawBody;
  }
  const decompressedStream = new Blob([new Uint8Array(rawBody)])
    .stream()
    .pipeThrough(new DecompressionStream("gzip"));
  return readStreamBounded(decompressedStream, maxBytes);
}

async function readStreamBounded(stream: ReadableStream<Uint8Array>, maxBytes: number): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value !== undefined) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel();
          throw new PayloadTooLargeError("Request body exceeds limit");
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

type ResolvedEnv = { [K in keyof Env]?: string | undefined };

function resolveEnv(runtimeEnv?: ResolvedEnv): ResolvedEnv {
  const procEnv: Record<string, string | undefined> =
    typeof process !== "undefined" && typeof process.env === "object" && process.env !== null
      ? process.env
      : {};
  return {
    SCOPEDB_ENDPOINT: runtimeEnv?.SCOPEDB_ENDPOINT ?? procEnv["SCOPEDB_ENDPOINT"],
    SCOPEDB_API_KEY: runtimeEnv?.SCOPEDB_API_KEY ?? procEnv["SCOPEDB_API_KEY"],
    VERCEL_DRAIN_SECRET: runtimeEnv?.VERCEL_DRAIN_SECRET ?? procEnv["VERCEL_DRAIN_SECRET"],
    DRAIN_AUTH_TOKEN: runtimeEnv?.DRAIN_AUTH_TOKEN ?? procEnv["DRAIN_AUTH_TOKEN"],
    VERCEL_VERIFY_TOKEN: runtimeEnv?.VERCEL_VERIFY_TOKEN ?? procEnv["VERCEL_VERIFY_TOKEN"],
    SCOPEDB_DATABASE: runtimeEnv?.SCOPEDB_DATABASE ?? procEnv["SCOPEDB_DATABASE"],
    SCOPEDB_SCHEMA: runtimeEnv?.SCOPEDB_SCHEMA ?? procEnv["SCOPEDB_SCHEMA"],
    SCOPEDB_TABLE: runtimeEnv?.SCOPEDB_TABLE ?? procEnv["SCOPEDB_TABLE"],
  };
}

function safeHttpStatus(status: unknown): number | null {
  if (typeof status === "number" && Number.isSafeInteger(status) && status >= 100 && status <= 599) {
    return status;
  }
  return null;
}

function nonEmptyString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function boundedString(value: string | null, maxLength: number): string | null {
  if (value === null || value.length === 0) {
    return null;
  }
  return value.length <= maxLength ? value : value.slice(0, maxLength);
}

function finiteNumber(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
    return null;
  }
  return value;
}

function sanitizeValue(value: unknown, depth: number, ancestors: Set<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      return String(value);
    }
    return value;
  }
  if (typeof value === "bigint") {
    return value >= MIN_INT64 && value <= MAX_INT64 ? value : value.toString();
  }
  if (value === undefined) {
    return null;
  }
  if (typeof value !== "object") {
    return String(value);
  }
  if (value instanceof Date) {
    const time = Date.prototype.getTime.call(value);
    return Number.isFinite(time) ? Date.prototype.toISOString.call(value) : "Invalid Date";
  }
  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      ...(typeof value.stack === "string" ? { stack: boundedString(value.stack, MAX_STACK_LENGTH) } : {}),
    };
  }
  if (ancestors.has(value)) {
    return "[Circular]";
  }
  if (depth >= MAX_SANITIZE_DEPTH) {
    return "[MaxDepth]";
  }
  if (!Array.isArray(value) && !isPlainObject(value)) {
    return String(value);
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return Array.from(value, (item) => sanitizeValue(item, depth + 1, ancestors));
    }
    const sanitized: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || descriptor.value === undefined) {
        continue;
      }
      sanitized[key] = sanitizeValue(descriptor.value, depth + 1, ancestors);
    }
    return sanitized;
  } finally {
    ancestors.delete(value);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requiredBinding(value: unknown, name: string): string {
  const normalized = nonEmptyString(value);
  if (normalized === null) {
    throw new Error(`Missing configuration: ${name}`);
  }
  return normalized;
}
