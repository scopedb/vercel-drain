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

  it("normalizes Log Drains, Web Analytics Drains, and Speed Insights Drains while redacting sensitive URLs", async () => {
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
          path: "/reset-password/secret_reset_token_999?utm_source=github&utm_medium=readme&ref=oss&tenant=acme&secret=top_secret",
          statusCode: 504,
          region: "sfo1",
          vercelCache: "MISS",
          referer: "https://github.com/scopedb/vercel-drain?token=private",
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
        queryParams: "utm_source=x&utm_campaign=launch&tenant=acme&api_key=leak_me",
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
        SCOPEDB_ALLOWED_QUERY_PARAMS: "tenant",
        SCOPEDB_REDACT_PATH_PREFIXES: "/reset-password",
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
    assert.equal(reqRow["path"], "/reset-password/:redacted");
    assert.equal(reqRow["status"], 504);
    assert.equal(reqRow["request_id"], "iad1::sfo1::12345");

    const reqAttrs = reqRow["attributes"] as Record<string, unknown>;
    assert.equal(reqAttrs["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    assert.equal(reqAttrs["span_id"], "00f067aa0ba902b7");
    assert.equal(reqAttrs["utm_source"], "github");
    assert.equal(reqAttrs["utm_medium"], "readme");
    assert.equal(reqAttrs["ref"], "oss");
    assert.deepEqual(reqAttrs["query"], { tenant: "acme" });
    assert.equal(reqAttrs["referer_host"], "github.com");
    assert.equal(reqAttrs["referer_path"], "/scopedb/vercel-drain");
    assert.equal(reqAttrs["vercel_cache"], "MISS");

    assert.equal(logRow["event_type"], "vercel.log");
    assert.equal(logRow["level"], "error");
    assert.equal(logRow["message"], "Unhandled rejection: upstream timeout");

    assert.equal(pageviewRow["event_type"], "vercel.pageview");
    assert.equal(pageviewRow["path"], "/docs/quickstart");
    const pvAttrs = pageviewRow["attributes"] as Record<string, unknown>;
    assert.equal(pvAttrs["utm_source"], "x");
    assert.equal(pvAttrs["utm_campaign"], "launch");
    assert.deepEqual(pvAttrs["query"], { tenant: "acme" });
    assert.equal(pvAttrs["country"], "US");

    assert.equal(vitalRow["event_type"], "vercel.web_vital");
    assert.equal(vitalRow["message"], "LCP 1840.5 (good)");

    const serialized = JSON.stringify(batch.rows);
    assert.ok(!serialized.includes("secret_reset_token_999"));
    assert.ok(!serialized.includes("top_secret"));
    assert.ok(!serialized.includes("leak_me"));
    assert.ok(!serialized.includes("token=private"));
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
