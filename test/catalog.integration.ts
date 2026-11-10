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
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { it } from "node:test";
import { Client, type CatalogTable, type CatalogView } from "scopedb";
import YAML from "yaml";
import { drainItemToRows } from "../src/index.js";

it("executes catalog views against current and historical event rows", { timeout: 60_000 }, async () => {
  const endpoint = process.env["SCOPEDB_TEST_ENDPOINT"];
  assert.ok(endpoint, "Set SCOPEDB_TEST_ENDPOINT to a local ScopeDB test server");
  const client = new Client(endpoint, { headers: { "X-ScopeDB-Tenant-Id": "__system__" } });
  const database = "vercel_test_" + randomUUID().replaceAll("-", "");
  const table = YAML.parse(await readFile(new URL("../../catalog/table.yaml", import.meta.url), "utf8")) as CatalogTable;
  const views: CatalogView[] = [];
  for (const name of ["requests", "pageviews", "errors", "ai_bots"]) {
    const view = YAML.parse(await readFile(new URL("../../catalog/v_vercel_" + name + ".yaml", import.meta.url), "utf8")) as CatalogView;
    view.statement = view.statement.replaceAll("scopedb.public.", database + ".public.");
    views.push(view);
  }
  await client.catalog().database(database).apply({ name: database, schemas: [{ name: "public", tables: [table], views }] });
  try {
    function requestItem(service: string, path: string, userAgent = "Mozilla/5.0", extra: Record<string, unknown> = {}) {
      return {
        id: randomUUID(),
        timestamp: 1730620800000,
        projectName: service,
        source: "edge",
        proxy: {
          method: "GET",
          host: "example.com",
          path,
          statusCode: 200,
          userAgent: [userAgent],
        },
        ...extra,
      };
    }

    const rows = [
      requestItem("document", "/docs?utm_source=first&utm_source=last&tag=a&tag=b"),
      requestItem("api-route", "/api/health"),
      requestItem("static-chunk", "/_next/static/chunks/main.js"),
      requestItem("claimed-ai", "/docs", "ChatGPT-User/1.0"),
      requestItem("markdown-only", "/docs.md", "Mozilla/5.0"),
      requestItem("ai-markdown", "/llms.txt", "ClaudeBot/1.0"),
      {
        schema: "vercel.analytics.v2",
        eventType: "pageview",
        timestamp: 1730620805000,
        projectName: "web-analytics",
        origin: "https://example.com",
        path: "/pricing",
        queryParams: "utm_source=beacon",
      },
      requestItem("logged-error", "/checkout", "Mozilla/5.0", {
        source: "lambda",
        level: "error",
        message: "upstream failed",
      }),
    ].flatMap((item) => drainItemToRows(item));

    const [legacy] = drainItemToRows(requestItem("legacy", "/docs"));
    delete legacy!.attributes["query"];
    legacy!.attributes["utm_source"] = "legacy-campaign";
    rows.push(legacy!);

    await client.table(table.name, { database }).append(rows.map((row) => JSON.stringify(row)).join("\n"));

    async function query(statement: string) {
      return (await client.query(statement, { signal: AbortSignal.timeout(15_000) })).toObjects();
    }

    const source = database + ".public.";
    assert.deepEqual(
      await query(
        "FROM " + source + "v_vercel_requests WHERE service = 'document' SELECT utm_source, query['tag'][1]::string AS second_tag",
      ),
      [{ utm_source: "first", second_tag: "b" }],
    );
    assert.deepEqual(await query("FROM " + source + "v_vercel_requests WHERE service = 'legacy' SELECT utm_source"), [
      { utm_source: "legacy-campaign" },
    ]);
    assert.deepEqual(
      await query("FROM " + source + "v_vercel_pageviews SELECT service, event_type ORDER BY service"),
      [
        { service: "document", event_type: "vercel.request" },
        { service: "legacy", event_type: "vercel.request" },
        { service: "logged-error", event_type: "vercel.request" },
        { service: "web-analytics", event_type: "vercel.pageview" },
      ],
    );
    assert.deepEqual(
      await query("FROM " + source + "v_vercel_ai_bots SELECT service, is_ai_user_agent, is_markdown_request ORDER BY service"),
      [
        { service: "ai-markdown", is_ai_user_agent: true, is_markdown_request: true },
        { service: "claimed-ai", is_ai_user_agent: true, is_markdown_request: false },
        { service: "markdown-only", is_ai_user_agent: false, is_markdown_request: true },
      ],
    );
    assert.deepEqual(await query("FROM " + source + "v_vercel_errors SELECT service, event_type"), [
      { service: "logged-error", event_type: "vercel.log" },
    ]);
  } finally {
    await client.catalog().database(database).delete({ allowDestructive: true });
  }
});
