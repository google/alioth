// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { Hono } from "hono";
import { Bindings } from "./types.ts";
import api from "./routes/api.ts";
import ui from "./routes/ui.tsx";

const app = new Hono<{ Bindings: Bindings }>();

app.route("/api", api);
app.route("/", ui);

export default {
  fetch: app.fetch,
  async scheduled(event: any, env: Bindings, ctx: any) {
    // Default retention is 90 days, configurable via env variables
    const retentionDays = env.RETENTION_DAYS || 90;

    // 1. Find all reports older than the retention period
    const { results } = await env.DB.prepare(
      "SELECT commit_sha FROM coverage_reports WHERE commit_timestamp <= datetime('now', ?)",
    )
      .bind(`-${retentionDays} days`)
      .all();

    if (results && results.length > 0) {
      // 2. Delete the raw JSON coverage maps from R2 Blob Storage
      const keysToDelete = results.map(
        (r: any) => `coverage-${r.commit_sha}.json`,
      );
      await env.COVERAGE_BUCKET.delete(keysToDelete);

      // 3. Delete the metadata records from D1 SQLite
      await env.DB.prepare(
        "DELETE FROM coverage_reports WHERE commit_timestamp <= datetime('now', ?)",
      )
        .bind(`-${retentionDays} days`)
        .run();
    }
  },
};
