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

import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { gunzipSync, gzipSync } from "node:zlib";
import { type CatalogTable, type CatalogView, Client } from "scopedb";
import YAML from "yaml";
import {
  createVercelDrainHandler,
  drainItemToRows,
  drainItemsToRows,
  verifyVercelSignature,
} from "../src/index.js";

function signPayload(body: string | Uint8Array, secret: string): string {
  return createHmac("sha1", secret).update(body).digest("hex");
}

describe("vercel-drain", () => {
  it("handles x-vercel-verify handshakes and enforces HMAC-SHA1 or Bearer authentication", async () => {
    const handler = createVercelDrainHandler({
      fetch: async () => Response.json({ num_rows_inserted: 0 }),
    });

    const env = {
      SCOPEDB_ENDPOINT: "https://workspace.scopedb.cloud",
      SCOPEDB_API_KEY: "test-api-key",
      VERCEL_DRAIN_SECRET: "drain-signing-secret",
      VERCEL_VERIFY_TOKEN: "verify-challenge-123",
    };

    const getRes = await handler.fetch(new Request("https://drain.example.com/api/vercel-drain"), env);
    assert.equal(getRes.status, 200);
    assert.equal(getRes.headers.get("x-vercel-verify"), "verify-challenge-123");

    const emptyPostRes = await handler.fetch(
      new Request("https://drain.example.com/api/vercel-drain", { method: "POST" }),
      env,
    );
    assert.equal(emptyPostRes.status, 200);
    assert.equal(emptyPostRes.headers.get("x-vercel-verify"), "verify-challenge-123");

    const unauthRes = await handler.fetch(
      new Request("https://drain.example.com/api/vercel-drain", {
        method: "POST",
        headers: { "x-vercel-signature": "0000000000000000000000000000000000000000" },
        body: '{"id":"1"}',
      }),
      env,
    );
    assert.equal(unauthRes.status, 401);

    const rawBytes = new TextEncoder().encode('{"id":"1"}');
    const validSig = signPayload(rawBytes, "drain-signing-secret");
    assert.equal(await verifyVercelSignature(rawBytes, validSig, "drain-signing-secret"), true);
    assert.equal(await verifyVercelSignature(rawBytes, `sha1=${validSig}`, "drain-signing-secret"), true);
    assert.equal(await verifyVercelSignature(rawBytes, validSig, "wrong-secret"), false);
  });

  it("normalizes Log Drains, Web Analytics Drains, and Speed Insights Drains with multi-value query capture and path token redaction", async () => {
    const ingestedBatches: { url: string; headers: Headers; rows: Record<string, unknown>[] }[] = [];

    const handler = createVercelDrainHandler({
      fetch: async (input, init) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        const headers = new Headers(init?.headers);
        const rawBody = init?.body;
        assert.ok(rawBody instanceof Uint8Array || rawBody instanceof ArrayBuffer);
        const decompressed = gunzipSync(
          rawBody instanceof Uint8Array ? rawBody : new Uint8Array(rawBody),
        ).toString("utf8");
        const rows = decompressed
          .trim()
          .split("\n")
          .filter((line) => line.length > 0)
          .map((line) => JSON.parse(line) as Record<string, unknown>);
        ingestedBatches.push({ url, headers, rows });
        return Response.json({ num_rows_inserted: rows.length });
      },
    });

    const ndjsonLines = [
      JSON.stringify({
        id: "req_log_1",
        timestamp: 1730620800000,
        projectId: "prj_123",
        projectName: "acme-web",
        deploymentId: "dpl_abc",
        environment: "production",
        branch: "main",
        source: "lambda",
        level: "error",
        message: "Unhandled rejection: upstream timeout",
        entrypoint: "/api/chat",
        executionRegion: "iad1",
        requestId: "iad1::sfo1::12345",
        durationMs: 312.4,
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        proxy: {
          timestamp: 1730620800000,
          method: "POST",
          host: "acme.example.com",
          path: "/reset/tok_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1?utm_source=github&utm_medium=readme&ref=oss&tenant=acme&tag=a&tag=b",
          statusCode: 504,
          region: "sfo1",
          vercelCache: "MISS",
          referer: "https://github.com/scopedb/vercel-drain?token=private#frag",
          userAgent: ["ClaudeBot/1.0 (+https://www.anthropic.com)"],
        },
      }),
      JSON.stringify({
        schema: "vercel.analytics.v2",
        eventType: "pageview",
        timestamp: 1730620810000,
        projectId: "prj_123",
        projectName: "acme-web",
        deployment: "dpl_abc",
        vercelEnvironment: "production",
        sessionId: 987654,
        origin: "https://acme.example.com",
        path: "/docs/quickstart",
        route: "/docs/[slug]",
        queryParams: "utm_source=x&utm_campaign=launch&tenant=acme&plan=team&plan=free",
        referrer: "https://t.co/xyz?secret=1",
        country: "US",
        region: "CA",
        city: "San Francisco",
        deviceType: "desktop",
        osName: "Mac OS",
        clientName: "Chrome",
      }),
      JSON.stringify({
        schema: "vercel.speed_insights.v1",
        id: "vital_1",
        timestamp: 1730620820000,
        projectId: "prj_123",
        projectName: "acme-web",
        deployment: "dpl_abc",
        vercelEnvironment: "production",
        origin: "https://acme.example.com",
        path: "/docs/quickstart",
        route: "/docs/[slug]",
        metricType: "LCP",
        value: 1840.5,
        rating: "good",
        country: "US",
        deviceType: "desktop",
      }),
    ].join("\n");

    const compressedPayload = gzipSync(Buffer.from(ndjsonLines, "utf8"));
    const signature = signPayload(compressedPayload, "drain-signing-secret");

    const response = await handler.fetch(
      new Request("https://drain.example.com/api/vercel-drain", {
        method: "POST",
        headers: {
          "content-type": "application/x-ndjson",
          "content-encoding": "gzip",
          "x-vercel-signature": signature,
        },
        body: compressedPayload,
      }),
      {
        SCOPEDB_ENDPOINT: "https://workspace.scopedb.cloud",
        SCOPEDB_API_KEY: "test-api-key",
        VERCEL_DRAIN_SECRET: "drain-signing-secret",
      },
    );

    assert.equal(response.status, 200);
    const responseBody = (await response.json()) as { num_rows_inserted: number };
    assert.equal(responseBody.num_rows_inserted, 4);
    assert.equal(ingestedBatches.length, 1);

    const batch = ingestedBatches[0]!;
    assert.equal(
      batch.url,
      "https://workspace.scopedb.cloud/v1/catalog/databases/scopedb/schemas/public/tables/vercel_events/ingest",
    );
    assert.equal(batch.rows.length, 4);

    const [reqRow, logRow, pageviewRow, vitalRow] = batch.rows as [
      Record<string, unknown>,
      Record<string, unknown>,
      Record<string, unknown>,
      Record<string, unknown>,
    ];

    assert.equal(reqRow["service"], "acme-web");
    assert.equal(reqRow["event_type"], "vercel.request");
    assert.equal(reqRow["outcome"], "error");
    assert.equal(reqRow["level"], "error");
    assert.equal(reqRow["method"], "POST");
    assert.equal(reqRow["host"], "acme.example.com");
    assert.equal(reqRow["path"], "/reset/REDACTED");
    assert.equal(reqRow["status"], 504);
    assert.equal(reqRow["request_id"], "iad1::sfo1::12345");

    const reqAttrs = reqRow["attributes"] as Record<string, unknown>;
    assert.equal(reqAttrs["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    assert.equal(reqAttrs["span_id"], "00f067aa0ba902b7");
    assert.equal("utm_source" in reqAttrs, false);
    assert.deepEqual(reqAttrs["query"], {
      utm_source: ["github"],
      utm_medium: ["readme"],
      ref: ["oss"],
      tenant: ["acme"],
      tag: ["a", "b"],
    });
    assert.equal(reqAttrs["referer_host"], "github.com");
    assert.equal(reqAttrs["referer_path"], "/scopedb/vercel-drain");
    assert.equal(reqAttrs["vercel_cache"], "MISS");

    assert.equal(logRow["event_type"], "vercel.log");
    assert.equal(logRow["level"], "error");
    assert.equal(logRow["path"], "/reset/REDACTED");
    assert.equal(logRow["message"], "Unhandled rejection: upstream timeout");

    assert.equal(pageviewRow["event_type"], "vercel.pageview");
    assert.equal(pageviewRow["path"], "/docs/quickstart");
    const pvAttrs = pageviewRow["attributes"] as Record<string, unknown>;
    assert.equal("utm_source" in pvAttrs, false);
    assert.deepEqual(pvAttrs["query"], {
      utm_source: ["x"],
      utm_campaign: ["launch"],
      tenant: ["acme"],
      plan: ["team", "free"],
    });
    assert.equal(pvAttrs["country"], "US");

    assert.equal(vitalRow["event_type"], "vercel.web_vital");
    assert.equal(vitalRow["message"], "LCP 1840.5 (good)");

    const serialized = JSON.stringify(batch.rows);
    assert.ok(!serialized.includes("tok_a1a1a1a1"));
    assert.ok(!serialized.includes("token=private"));
    assert.ok(!serialized.includes("secret=1"));
  });

  it("preserves decoded query values and duplicates without silently clipping user data", () => {
    const params = new URLSearchParams();
    for (let i = 0; i < 40; i++) params.append("tag", `value-${i}`);
    params.append("utm_source", "first");
    params.append("utm_source", "last");
    params.append("payload", "x".repeat(4096));
    params.append("email", "alice@example.com");
    params.append("token", "tok_" + "ab12".repeat(16));
    params.append("__proto__", "ordinary query key");
    params.append("empty", "");

    const [row] = drainItemToRows({
      id: "1",
      projectName: "acme-web",
      proxy: {
        method: "GET",
        host: "example.com",
        path: `/?${params}`,
        statusCode: 200,
      },
    });
    assert.deepEqual(
      row!.attributes["query"],
      Object.fromEntries([...new Set(params.keys())].map((key) => [key, params.getAll(key)])),
    );
  });

  it("redacts encoded and prefixed path credentials in requests and Referer headers", () => {
    for (const token of [
      "ab12".repeat(16),
      "tok_" + "ab12".repeat(16),
      "tok_12345678-abcd-1234-abcd-123456789abc",
      "AbCd12EfGh34IjKl56MnOp",
      "4111-1111-1111-1111",
    ]) {
      const encoded = [...token].map((char) => `%${char.charCodeAt(0).toString(16)}`).join("");
      const rows = drainItemToRows({
        id: "1",
        projectName: "acme-web",
        source: "lambda",
        level: "error",
        message: "request failed",
        proxy: {
          method: "GET",
          host: "example.com",
          path: `/reset/${encoded}`,
          statusCode: 500,
          referer: `https://example.com/reset/${token}?secret=hidden`,
        },
      });
      assert.ok(rows.every((row) => row.path === "/reset/REDACTED"));
      assert.equal(rows[0]!.attributes["referer_path"], "/reset/REDACTED");
      assert.ok(!JSON.stringify(rows).includes(token));
    }
  });

  it("applies optional URL capture policy before sending records", async () => {
    const handler = createVercelDrainHandler({
      allowedQueryParams: ["tag", "code"],
      redactQueryValue: (key, value) => (key === "code" ? null : value.toUpperCase()),
      redactPath: (path) => (path.startsWith("/reset/") ? "/reset/:token" : path),
      fetch: async (_input, init) => {
        const rows = gunzipSync(init!.body as Uint8Array)
          .toString()
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        assert.deepEqual(rows[0].attributes.query, { tag: ["A", "B"] });
        assert.equal(rows[0].path, "/reset/:token");
        assert.equal(rows[0].attributes.referer_path, "/reset/:token");
        assert.ok(!JSON.stringify(rows).includes("short-secret"));
        return Response.json({ num_rows_inserted: rows.length });
      },
    });

    const payload = JSON.stringify({
      id: "1",
      projectName: "acme-web",
      proxy: {
        method: "GET",
        host: "example.com",
        path: "/reset/short-secret?tag=a&tag=b&code=short-secret&email=alice%40example.com",
        statusCode: 200,
        referer: "https://example.com/reset/short-secret",
      },
    });
    const res = await handler.fetch(
      new Request("https://drain.example.com/api/vercel-drain", {
        method: "POST",
        headers: {
          "content-type": "application/x-ndjson",
          "x-vercel-signature": signPayload(payload, "drain-signing-secret"),
        },
        body: payload,
      }),
      {
        SCOPEDB_ENDPOINT: "https://example.invalid",
        SCOPEDB_API_KEY: "test",
        VERCEL_DRAIN_SECRET: "drain-signing-secret",
      },
    );
    assert.equal(res.status, 200);

    const [omitted] = drainItemToRows(
      {
        id: "2",
        projectName: "acme-web",
        proxy: {
          method: "GET",
          host: "example.com",
          path: "/reset/short-secret?tag=a",
          statusCode: 200,
        },
      },
      {
        allowedQueryParams: [],
        redactPath: () => null,
      },
    );
    assert.equal(omitted!.path, null);
    assert.deepEqual(omitted!.attributes["query"], {});
  });

  it("reports uncertain delivery without replaying a possibly committed batch", async () => {
    let calls = 0;
    const handler = createVercelDrainHandler({
      fetch: async () => {
        calls++;
        throw new TypeError("connection lost");
      },
    });
    const payload = JSON.stringify({
      id: "1",
      projectName: "acme-web",
      proxy: { method: "GET", host: "example.com", path: "/", statusCode: 200 },
    });
    await assert.rejects(
      handler.fetch(
        new Request("https://drain.example.com/api/vercel-drain", {
          method: "POST",
          headers: { "x-vercel-signature": signPayload(payload, "drain-signing-secret") },
          body: payload,
        }),
        {
          SCOPEDB_ENDPOINT: "https://example.invalid",
          SCOPEDB_API_KEY: "test",
          VERCEL_DRAIN_SECRET: "drain-signing-secret",
        },
      ),
    );
    assert.equal(calls, 1);
  });

  it("validates Catalog YAML table and view definitions against the ScopeDB SDK and emitted row columns", async () => {
    const tableDef = YAML.parse(
      await readFile(new URL("../../catalog/table.yaml", import.meta.url), "utf8"),
    ) as CatalogTable;

    const client = new Client("https://workspace.scopedb.cloud", {
      apiKey: "test-key",
      fetch: async (_input, init) => {
        const body = JSON.parse(String(init?.body)) as unknown;
        return new Response(
          JSON.stringify({ before: null, after: body, destructive: false }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", ETag: '"v1"' },
          },
        );
      },
    });

    const tableResult = await client
      .catalog()
      .table("scopedb", "public", "vercel_events")
      .apply(tableDef);
    assert.equal(tableResult.after?.name, "vercel_events");

    const expectedColumns = (tableDef.columns ?? []).map((col) => col.name);
    const sampleRows = drainItemsToRows([
      {
        id: "1",
        projectName: "acme-web",
        source: "lambda",
        message: "ok",
        proxy: { method: "GET", host: "acme.example.com", path: "/", statusCode: 200 },
      },
      {
        schema: "vercel.analytics.v2",
        eventType: "pageview",
        projectName: "acme-web",
        origin: "https://acme.example.com",
        path: "/",
      },
      {
        schema: "vercel.speed_insights.v1",
        projectName: "acme-web",
        origin: "https://acme.example.com",
        path: "/",
        metricType: "LCP",
        value: 1200,
      },
    ]);
    for (const row of sampleRows) {
      assert.deepEqual(Object.keys(row), expectedColumns);
    }

    for (const viewName of [
      "v_vercel_requests",
      "v_vercel_pageviews",
      "v_vercel_errors",
      "v_vercel_ai_bots",
    ]) {
      const viewDef = YAML.parse(
        await readFile(new URL(`../../catalog/${viewName}.yaml`, import.meta.url), "utf8"),
      ) as CatalogView;
      const viewResult = await client.catalog().view("scopedb", "public", viewName).apply(viewDef);
      assert.equal(viewResult.after?.name, viewName);
    }
  });
});
