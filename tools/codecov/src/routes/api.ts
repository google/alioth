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
import { Bindings } from "../types.ts";

const api = new Hono<{ Bindings: Bindings }>();

// API: Upload coverage
// Expected payload: { commit_sha: "abc1234", branch: "main", coverage_pct: 85.5, report: { "src/main.rs": { "1": 1, "2": 0 } } }
api.post("/upload", async (c) => {
  const expectedToken = c.env.CODECOV_TOKEN;
  if (expectedToken) {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || authHeader !== `Bearer ${expectedToken}`) {
      return c.json({ error: "Unauthorized" }, 401);
    }
  }

  const body = await c.req.json();
  const {
    commit_sha,
    branch,
    commit_timestamp,
    coverage_pct,
    delta_coverage_pct,
    report,
    pr_number,
    base_sha,
  } = body;

  if (
    !commit_sha ||
    !branch ||
    !commit_timestamp ||
    coverage_pct === undefined ||
    !report
  ) {
    return c.json({ error: "Missing required fields" }, 400);
  }

  // 1. Insert metadata into D1
  try {
    if (pr_number) {
      await c.env.DB.prepare(
        "INSERT INTO pr_reports (pr_number, head_sha, base_sha, commit_timestamp, coverage_pct, delta_coverage_pct) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(pr_number) DO UPDATE SET head_sha = excluded.head_sha, base_sha = excluded.base_sha, commit_timestamp = excluded.commit_timestamp, coverage_pct = excluded.coverage_pct, delta_coverage_pct = excluded.delta_coverage_pct",
      )
        .bind(
          pr_number,
          commit_sha,
          base_sha || "",
          commit_timestamp,
          coverage_pct,
          delta_coverage_pct ?? null,
        )
        .run();
    } else {
      await c.env.DB.prepare(
        "INSERT INTO coverage_reports (commit_sha, branch, commit_timestamp, coverage_pct, delta_coverage_pct) VALUES (?, ?, ?, ?, ?) ON CONFLICT(commit_sha) DO UPDATE SET coverage_pct = excluded.coverage_pct, delta_coverage_pct = excluded.delta_coverage_pct, branch = excluded.branch, commit_timestamp = excluded.commit_timestamp",
      )
        .bind(
          commit_sha,
          branch,
          commit_timestamp,
          coverage_pct,
          delta_coverage_pct ?? null,
        )
        .run();
    }
  } catch (e: any) {
    return c.json({ error: "Database error", details: e.message }, 500);
  }

  // 2. Store JSON payload in R2
  if (pr_number) {
    await c.env.COVERAGE_BUCKET.put(
      `pr-${pr_number}.json`,
      JSON.stringify(report),
    );
  } else {
    await c.env.COVERAGE_BUCKET.put(
      `coverage-${commit_sha}.json`,
      JSON.stringify(report),
    );
  }

  return c.json({ success: true, commit_sha });
});

// API: Get latest coverage percentage
api.get("/coverage", async (c) => {
  const branch = c.req.query("branch") || "main";
  const result = await c.env.DB.prepare(
    "SELECT coverage_pct FROM coverage_reports WHERE branch = ? ORDER BY commit_timestamp DESC LIMIT 1",
  )
    .bind(branch)
    .first();

  if (!result) {
    return c.json({ error: "No coverage data found for this branch" }, 404);
  }

  return c.json({ branch, coverage_pct: result.coverage_pct });
});

// API: Shields.io dynamic badge endpoint
api.get("/badge", async (c) => {
  const branch = c.req.query("branch") || "main";
  const result = await c.env.DB.prepare(
    "SELECT coverage_pct FROM coverage_reports WHERE branch = ? ORDER BY commit_timestamp DESC LIMIT 1",
  )
    .bind(branch)
    .first();

  if (!result) {
    return c.json({
      schemaVersion: 1,
      label: "coverage",
      message: "unknown",
      color: "lightgrey",
    });
  }

  const pct = result.coverage_pct as number;
  let color = "red";
  if (pct >= 80) color = "success";
  else if (pct >= 60) color = "yellow";

  return c.json({
    schemaVersion: 1,
    label: "coverage",
    message: `${pct.toFixed(2)}%`,
    color,
  });
});

export default api;
