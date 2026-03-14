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
import { Layout } from "../components/Layout.tsx";
import { formatDate, buildTree, flattenTree } from "../utils.ts";

const ui = new Hono<{ Bindings: Bindings }>();

// UI: Home page (list recent coverage reports)
ui.get("/", async (c) => {
  const { results: branches } = await c.env.DB.prepare(
    "SELECT branch, commit_sha, coverage_pct, MAX(commit_timestamp) as commit_timestamp FROM coverage_reports GROUP BY branch ORDER BY commit_timestamp DESC",
  ).all();

  const { results: commits } = await c.env.DB.prepare(
    "SELECT * FROM coverage_reports ORDER BY commit_timestamp DESC LIMIT 50",
  ).all();

  const { results: prs } = await c.env.DB.prepare(
    "SELECT * FROM pr_reports ORDER BY commit_timestamp DESC LIMIT 50",
  ).all();

  return c.html(
    <Layout title="Dashboard" projectName={c.env.PROJECT_NAME || "Repository"}>
      <h2>Branches</h2>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Branch</th>
              <th>Latest Commit</th>
              <th class="right-align">Overall Coverage</th>
              <th>Last Updated</th>
            </tr>
          </thead>
          <tbody>
            {branches.map((b: any) => (
              <tr>
                <td>
                  <strong>{b.branch}</strong>
                </td>
                <td>
                  <a href={`/commit/${b.commit_sha}`}>
                    <code>{b.commit_sha.substring(0, 7)}</code>
                  </a>
                </td>
                <td class="right-align">
                  <span
                    class={
                      b.coverage_pct >= 80
                        ? "pct-high"
                        : b.coverage_pct >= 60
                          ? "pct-medium"
                          : "pct-low"
                    }
                  >
                    {b.coverage_pct.toFixed(2)}%
                  </span>
                </td>
                <td>{formatDate(b.commit_timestamp)}</td>
              </tr>
            ))}
            {branches.length === 0 && (
              <tr>
                <td colSpan={4}>No branches found.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h2>Recent Pull Requests</h2>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>PR</th>
              <th class="right-align">Overall Coverage</th>
              <th class="right-align">Patch Coverage</th>
              <th>Last Updated</th>
            </tr>
          </thead>
          <tbody>
            {prs.map((r: any) => (
              <tr>
                <td>
                  <a href={`/pr/${r.pr_number}`}>
                    <strong>#{r.pr_number}</strong>
                  </a>
                </td>
                <td class="right-align">
                  <span
                    class={
                      r.coverage_pct >= 80
                        ? "pct-high"
                        : r.coverage_pct >= 60
                          ? "pct-medium"
                          : "pct-low"
                    }
                  >
                    {r.coverage_pct.toFixed(2)}%
                  </span>
                </td>
                <td class="right-align">
                  {r.delta_coverage_pct !== null ? (
                    <span
                      class={
                        r.delta_coverage_pct >= 80
                          ? "pct-high"
                          : r.delta_coverage_pct >= 60
                            ? "pct-medium"
                            : "pct-low"
                      }
                    >
                      {r.delta_coverage_pct.toFixed(2)}%
                    </span>
                  ) : (
                    "-"
                  )}
                </td>
                <td>{formatDate(r.commit_timestamp)}</td>
              </tr>
            ))}
            {prs.length === 0 && (
              <tr>
                <td colSpan={4}>No PR coverage reports uploaded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h2>Recent Commits</h2>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Commit</th>
              <th>Branch</th>
              <th class="right-align">Overall Coverage</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {commits.map((r: any) => (
              <tr>
                <td>
                  <a href={`/commit/${r.commit_sha}`}>
                    <code>{r.commit_sha.substring(0, 7)}</code>
                  </a>
                </td>
                <td>{r.branch}</td>
                <td class="right-align">
                  <span
                    class={
                      r.coverage_pct >= 80
                        ? "pct-high"
                        : r.coverage_pct >= 60
                          ? "pct-medium"
                          : "pct-low"
                    }
                  >
                    {r.coverage_pct.toFixed(2)}%
                  </span>
                </td>
                <td>{formatDate(r.commit_timestamp)}</td>
              </tr>
            ))}
            {commits.length === 0 && (
              <tr>
                <td colSpan={4}>No coverage reports uploaded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Layout>,
  );
});

// UI: Commit overview (list files)
ui.get("/commit/:sha", async (c) => {
  const sha = c.req.param("sha");

  if (!/^[0-9a-f]{7,40}$/i.test(sha)) {
    return c.text("Invalid commit SHA", 400);
  }

  const report = await c.env.DB.prepare(
    "SELECT * FROM coverage_reports WHERE commit_sha = ?",
  )
    .bind(sha)
    .first();

  if (!report) return c.text("Commit not found", 404);

  const object = await c.env.COVERAGE_BUCKET.get(`coverage-${sha}.json`);
  if (!object) return c.text("Coverage details not found in storage", 404);

  const coverageData: Record<string, any> = await object.json();
  const tree = buildTree(coverageData);
  const flatFiles = flattenTree(tree);

  const touchedFiles = Object.entries(coverageData)
    .filter(([_, data]) => (data as any).status)
    .map(([path, data]) => ({ path, ...(data as any) }))
    .sort((a, b) => a.path.localeCompare(b.path));

  const getStatusBadge = (status?: string) => {
    if (!status) return "";
    if (status === "A") {
      return (
        <span
          style={{ color: "#1a7f37", fontWeight: "bold", fontSize: "12px" }}
          title="Added"
        >
          A
        </span>
      ) as any;
    } else if (status === "M") {
      return (
        <span
          style={{ color: "#9a6700", fontWeight: "bold", fontSize: "12px" }}
          title="Modified"
        >
          M
        </span>
      ) as any;
    }
    return (
      <span
        style={{ color: "#57606a", fontWeight: "bold", fontSize: "12px" }}
        title={status}
      >
        {status}
      </span>
    ) as any;
  };

  c.header("Cache-Control", "public, max-age=31536000, immutable");
  return c.html(
    <Layout
      title={`Commit ${sha.substring(0, 7)}`}
      projectName={c.env.PROJECT_NAME || "Repository"}
    >
      <div class="breadcrumb">
        <a href="/">Home</a> / Commit <code>{sha.substring(0, 7)}</code>
      </div>
      <h2
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          flexWrap: "wrap",
        }}
      >
        <span>
          Commit: <code>{sha.substring(0, 12)}</code>
        </span>
        <button
          onclick={`navigator.clipboard.writeText('${sha}'); this.innerText='Copied!'; setTimeout(() => this.innerText='Copy', 2000);`}
          style={{
            padding: "4px 12px",
            fontSize: "13px",
            fontWeight: "500",
            cursor: "pointer",
            borderRadius: "var(--radius)",
            border: "1px solid var(--border-color)",
            background: "var(--surface-color)",
            color: "var(--text-secondary)",
            boxShadow: "0 1px 2px 0 rgb(0 0 0 / 0.05)",
          }}
        >
          Copy
        </button>
      </h2>
      <p>
        Overall Coverage:{" "}
        <span
          class={
            (report as any).coverage_pct >= 80
              ? "pct-high"
              : (report as any).coverage_pct >= 60
                ? "pct-medium"
                : "pct-low"
          }
        >
          {(report as any).coverage_pct.toFixed(2)}%
        </span>
        {(report as any).delta_coverage_pct !== null &&
          (report as any).delta_coverage_pct !== undefined && (
            <>
              {" "}
              &nbsp;|&nbsp; Patch Coverage:{" "}
              <span
                class={
                  (report as any).delta_coverage_pct >= 80
                    ? "pct-high"
                    : (report as any).delta_coverage_pct >= 60
                      ? "pct-medium"
                      : "pct-low"
                }
              >
                {(report as any).delta_coverage_pct.toFixed(2)}%
              </span>
            </>
          )}
      </p>

      {touchedFiles.length > 0 && (
        <>
          <h3>Changed Files</h3>
          <div class="table-responsive">
            <table>
              <thead>
                <tr>
                  <th style={{ width: "30px", paddingRight: "0" }}></th>
                  <th>File</th>
                  <th class="right-align">Coverage</th>
                  <th class="right-align">Patch Coverage</th>
                </tr>
              </thead>
              <tbody>
                {touchedFiles.map((f) => {
                  const pct = f.coverage_pct;
                  const pctDisplay =
                    pct !== undefined ? pct.toFixed(2) + "%" : "N/A";
                  const pctClass =
                    pct !== undefined
                      ? pct >= 80
                        ? "pct-high"
                        : pct >= 60
                          ? "pct-medium"
                          : "pct-low"
                      : "";

                  const deltaPct = f.delta_coverage_pct;
                  const deltaDisplay =
                    deltaPct !== undefined ? deltaPct.toFixed(2) + "%" : "-";
                  const deltaClass =
                    deltaPct !== undefined
                      ? deltaPct >= 80
                        ? "pct-high"
                        : deltaPct >= 60
                          ? "pct-medium"
                          : "pct-low"
                      : "";

                  return (
                    <tr>
                      <td
                        style={{
                          width: "30px",
                          paddingRight: "0",
                          textAlign: "center",
                        }}
                      >
                        {getStatusBadge(f.status)}
                      </td>
                      <td>
                        <a href={`/commit/${sha}/file/${f.path}`}>{f.path}</a>
                      </td>
                      <td class="right-align">
                        <span class={pctClass}>{pctDisplay}</span>
                      </td>
                      <td class="right-align">
                        <span class={deltaClass}>{deltaDisplay}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      <h3>Covered Files</h3>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th style={{ width: "30px", paddingRight: "0" }}></th>
              <th>File</th>
              <th class="right-align">Coverage</th>
            </tr>
          </thead>
          <tbody>
            {flatFiles.map((node) => {
              const pct = node.coverage_pct;
              const pctDisplay =
                pct !== undefined ? pct.toFixed(2) + "%" : "N/A";
              const pctClass =
                pct !== undefined
                  ? pct >= 80
                    ? "pct-high"
                    : pct >= 60
                      ? "pct-medium"
                      : "pct-low"
                  : "";

              return (
                <tr>
                  <td
                    style={{
                      width: "30px",
                      paddingRight: "0",
                      textAlign: "center",
                    }}
                  >
                    {node.type === "file" ? getStatusBadge(node.status) : ""}
                  </td>
                  <td style={{ paddingLeft: `${node.depth * 20 + 10}px` }}>
                    {node.type === "dir" ? (
                      <strong>{node.name}/</strong>
                    ) : (
                      <a href={`/commit/${sha}/file/${node.path}`}>
                        {node.name}
                      </a>
                    )}
                  </td>
                  <td class="right-align">
                    {node.type === "file" && (
                      <span class={pctClass}>{pctDisplay}</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Layout>,
  );
});

// UI: View specific file source code with coverage highlighting
ui.get("/commit/:sha/file/:path{.+}", async (c) => {
  const sha = c.req.param("sha");
  const filePath = c.req.param("path"); // Everything after /file/

  if (!filePath) return c.text("File path is missing", 400);

  if (!/^[0-9a-f]{7,40}$/i.test(sha)) {
    return c.text("Invalid commit SHA", 400);
  }

  if (filePath.includes("..") || filePath.startsWith("/")) {
    return c.text("Invalid file path", 400);
  }

  // 1. Fetch coverage data from R2
  const object = await c.env.COVERAGE_BUCKET.get(`coverage-${sha}.json`);
  if (!object) return c.text("Coverage details not found", 404);

  const coverageData: Record<string, any> = await object.json();
  const fileCoverage = coverageData[filePath] || {};
  const filePct = fileCoverage.coverage_pct;
  const deltaLines = fileCoverage.delta_lines || [];

  // 2. Fetch raw source code from GitHub
  const githubRepo = c.env.GITHUB_REPO || "google/alioth";
  const githubUrl = `https://raw.githubusercontent.com/${githubRepo}/${sha}/${filePath}`;
  const ghRes = await fetch(githubUrl);

  if (!ghRes.ok) {
    return c.html(
      <Layout title="Error" projectName={c.env.PROJECT_NAME || "Repository"}>
        <h2>File not found on GitHub</h2>
        <p>
          Attempted to fetch: <code>{githubUrl}</code>
        </p>
        <p>
          Status: {ghRes.status} {ghRes.statusText}
        </p>
        <p>
          <a href={`/commit/${sha}`}>&larr; Back to commit</a>
        </p>
      </Layout>,
      404,
    );
  }

  const sourceCode = await ghRes.text();
  const lines = sourceCode.split("\n");

  c.header("Cache-Control", "public, max-age=31536000, immutable");
  return c.html(
    <Layout
      title={`${filePath} - ${sha.substring(0, 7)}`}
      projectName={c.env.PROJECT_NAME || "Repository"}
    >
      <div class="breadcrumb">
        <a href="/">Home</a> /{" "}
        <a href={`/commit/${sha}`}>
          Commit <code>{sha.substring(0, 7)}</code>
        </a>{" "}
        / {filePath}
      </div>
      <h2>
        {filePath.split("/").pop()}
        {filePct !== undefined && (
          <span
            style={{ marginLeft: "15px", fontSize: "18px" }}
            class={
              filePct >= 80
                ? "pct-high"
                : filePct >= 60
                  ? "pct-medium"
                  : "pct-low"
            }
          >
            {filePct.toFixed(2)}%
          </span>
        )}
      </h2>

      <div class="source-code">
        <div class="source-code-inner">
          {lines.map((line, index) => {
            const lineNum = index + 1;
            const hits = fileCoverage[lineNum.toString()];

            let statusClass = "";
            if (hits !== undefined) {
              statusClass = hits > 0 ? "covered" : "uncovered";
            }

            const isDelta = deltaLines.includes(lineNum);

            return (
              <div class={`line ${statusClass}`}>
                <span class="line-number">{lineNum}</span>
                {isDelta ? (
                  <span class="line-change-marker" title="Added in this commit">
                    +
                  </span>
                ) : (
                  <span class="line-change-marker"></span>
                )}
                <code class="language-rust content">{line || " "}</code>
                {hits !== undefined && hits > 0 && (
                  <span class="hit-count" title={`${hits} hits`}>
                    {hits}x
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </Layout>,
  );
});

// UI: PR overview (list files)
ui.get("/pr/:pr_number", async (c) => {
  const pr_number = parseInt(c.req.param("pr_number"), 10);

  if (isNaN(pr_number)) {
    return c.text("Invalid PR number", 400);
  }

  const report = await c.env.DB.prepare(
    "SELECT * FROM pr_reports WHERE pr_number = ?",
  )
    .bind(pr_number)
    .first();

  if (!report) return c.text("PR not found", 404);

  const object = await c.env.COVERAGE_BUCKET.get(`pr-${pr_number}.json`);
  if (!object) return c.text("Coverage details not found in storage", 404);

  const coverageData: Record<string, any> = await object.json();
  const tree = buildTree(coverageData);
  const flatFiles = flattenTree(tree);

  const touchedFiles = Object.entries(coverageData)
    .filter(([_, data]) => (data as any).status)
    .map(([path, data]) => ({ path, ...(data as any) }))
    .sort((a, b) => a.path.localeCompare(b.path));

  const getStatusBadge = (status?: string) => {
    if (!status) return "";
    if (status === "A") {
      return (
        <span
          style={{ color: "#1a7f37", fontWeight: "bold", fontSize: "12px" }}
          title="Added"
        >
          A
        </span>
      ) as any;
    } else if (status === "M") {
      return (
        <span
          style={{ color: "#9a6700", fontWeight: "bold", fontSize: "12px" }}
          title="Modified"
        >
          M
        </span>
      ) as any;
    }
    return (
      <span
        style={{ color: "#57606a", fontWeight: "bold", fontSize: "12px" }}
        title={status}
      >
        {status}
      </span>
    ) as any;
  };

  const head_sha = report.head_sha as string;
  const githubRepo = c.env.GITHUB_REPO || "google/alioth";

  c.header("Cache-Control", "public, max-age=30"); // PRs can update, cache shortly
  return c.html(
    <Layout
      title={`PR #${pr_number}`}
      projectName={c.env.PROJECT_NAME || "Repository"}
    >
      <div class="breadcrumb">
        <a href="/">Home</a> / PR <code>#{pr_number}</code>
      </div>
      <h2
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          flexWrap: "wrap",
        }}
      >
        <span>
          <a
            href={`https://github.com/${githubRepo}/pull/${pr_number}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "inherit", textDecoration: "none" }}
          >
            Pull Request #{pr_number}
          </a>
        </span>
      </h2>
      <p style={{ fontSize: "14px", color: "var(--text-secondary)" }}>
        Head:{" "}
        <a
          href={`https://github.com/${githubRepo}/pull/${pr_number}/changes/${head_sha}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          <code>{head_sha.substring(0, 7)}</code>
        </a>{" "}
        | Base:{" "}
        <a
          href={`https://github.com/${githubRepo}/commit/${(report as any).base_sha}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          <code>{(report as any).base_sha.substring(0, 7)}</code>
        </a>
      </p>
      <p>
        Overall Coverage:{" "}
        <span
          class={
            (report as any).coverage_pct >= 80
              ? "pct-high"
              : (report as any).coverage_pct >= 60
                ? "pct-medium"
                : "pct-low"
          }
        >
          {(report as any).coverage_pct.toFixed(2)}%
        </span>
        {(report as any).delta_coverage_pct !== null &&
          (report as any).delta_coverage_pct !== undefined && (
            <>
              {" "}
              &nbsp;|&nbsp; Patch Coverage:{" "}
              <span
                class={
                  (report as any).delta_coverage_pct >= 80
                    ? "pct-high"
                    : (report as any).delta_coverage_pct >= 60
                      ? "pct-medium"
                      : "pct-low"
                }
              >
                {(report as any).delta_coverage_pct.toFixed(2)}%
              </span>
            </>
          )}
      </p>

      {touchedFiles.length > 0 && (
        <>
          <h3>Changed Files</h3>
          <div class="table-responsive">
            <table>
              <thead>
                <tr>
                  <th style={{ width: "30px", paddingRight: "0" }}></th>
                  <th>File</th>
                  <th class="right-align">Coverage</th>
                  <th class="right-align">Patch Coverage</th>
                </tr>
              </thead>
              <tbody>
                {touchedFiles.map((f) => {
                  const pct = f.coverage_pct;
                  const pctDisplay =
                    pct !== undefined ? pct.toFixed(2) + "%" : "N/A";
                  const pctClass =
                    pct !== undefined
                      ? pct >= 80
                        ? "pct-high"
                        : pct >= 60
                          ? "pct-medium"
                          : "pct-low"
                      : "";

                  const deltaPct = f.delta_coverage_pct;
                  const deltaDisplay =
                    deltaPct !== undefined ? deltaPct.toFixed(2) + "%" : "-";
                  const deltaClass =
                    deltaPct !== undefined
                      ? deltaPct >= 80
                        ? "pct-high"
                        : deltaPct >= 60
                          ? "pct-medium"
                          : "pct-low"
                      : "";

                  return (
                    <tr>
                      <td
                        style={{
                          width: "30px",
                          paddingRight: "0",
                          textAlign: "center",
                        }}
                      >
                        {getStatusBadge(f.status)}
                      </td>
                      <td>
                        <a href={`/pr/${pr_number}/file/${f.path}`}>{f.path}</a>
                      </td>
                      <td class="right-align">
                        <span class={pctClass}>{pctDisplay}</span>
                      </td>
                      <td class="right-align">
                        <span class={deltaClass}>{deltaDisplay}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      <h3>Covered Files</h3>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th style={{ width: "30px", paddingRight: "0" }}></th>
              <th>File</th>
              <th class="right-align">Coverage</th>
            </tr>
          </thead>
          <tbody>
            {flatFiles.map((node) => {
              const pct = node.coverage_pct;
              const pctDisplay =
                pct !== undefined ? pct.toFixed(2) + "%" : "N/A";
              const pctClass =
                pct !== undefined
                  ? pct >= 80
                    ? "pct-high"
                    : pct >= 60
                      ? "pct-medium"
                      : "pct-low"
                  : "";

              return (
                <tr>
                  <td
                    style={{
                      width: "30px",
                      paddingRight: "0",
                      textAlign: "center",
                    }}
                  >
                    {node.type === "file" ? getStatusBadge(node.status) : ""}
                  </td>
                  <td style={{ paddingLeft: `${node.depth * 20 + 10}px` }}>
                    {node.type === "dir" ? (
                      <strong>{node.name}/</strong>
                    ) : (
                      <a href={`/pr/${pr_number}/file/${node.path}`}>
                        {node.name}
                      </a>
                    )}
                  </td>
                  <td class="right-align">
                    {node.type === "file" && (
                      <span class={pctClass}>{pctDisplay}</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Layout>,
  );
});

// UI: View specific file source code for PR
ui.get("/pr/:pr_number/file/:path{.+}", async (c) => {
  const pr_number = parseInt(c.req.param("pr_number"), 10);
  const filePath = c.req.param("path");

  if (isNaN(pr_number)) return c.text("Invalid PR number", 400);
  if (!filePath) return c.text("File path is missing", 400);

  if (filePath.includes("..") || filePath.startsWith("/")) {
    return c.text("Invalid file path", 400);
  }

  const report = await c.env.DB.prepare(
    "SELECT head_sha FROM pr_reports WHERE pr_number = ?",
  )
    .bind(pr_number)
    .first();

  if (!report) return c.text("PR not found", 404);
  const sha = report.head_sha as string;

  // 1. Fetch coverage data from R2
  const object = await c.env.COVERAGE_BUCKET.get(`pr-${pr_number}.json`);
  if (!object) return c.text("Coverage details not found", 404);

  const coverageData: Record<string, any> = await object.json();
  const fileCoverage = coverageData[filePath] || {};
  const filePct = fileCoverage.coverage_pct;
  const deltaLines = fileCoverage.delta_lines || [];

  // 2. Fetch raw source code from GitHub
  const githubRepo = c.env.GITHUB_REPO || "google/alioth";
  const githubUrl = `https://raw.githubusercontent.com/${githubRepo}/${sha}/${filePath}`;
  const ghRes = await fetch(githubUrl);

  if (!ghRes.ok) {
    return c.html(
      <Layout title="Error" projectName={c.env.PROJECT_NAME || "Repository"}>
        <h2>File not found on GitHub</h2>
        <p>
          Attempted to fetch: <code>{githubUrl}</code>
        </p>
        <p>
          Status: {ghRes.status} {ghRes.statusText}
        </p>
        <p>
          <a href={`/pr/${pr_number}`}>&larr; Back to PR</a>
        </p>
      </Layout>,
      404,
    );
  }

  const sourceCode = await ghRes.text();
  const lines = sourceCode.split("\n");

  c.header("Cache-Control", "public, max-age=30");
  return c.html(
    <Layout
      title={`${filePath} - PR #${pr_number}`}
      projectName={c.env.PROJECT_NAME || "Repository"}
    >
      <div class="breadcrumb">
        <a href="/">Home</a> /{" "}
        <a href={`/pr/${pr_number}`}>
          PR <code>#{pr_number}</code>
        </a>{" "}
        / {filePath}
      </div>
      <h2>
        {filePath.split("/").pop()}
        {filePct !== undefined && (
          <span
            style={{ marginLeft: "15px", fontSize: "18px" }}
            class={
              filePct >= 80
                ? "pct-high"
                : filePct >= 60
                  ? "pct-medium"
                  : "pct-low"
            }
          >
            {filePct.toFixed(2)}%
          </span>
        )}
      </h2>

      <div class="source-code">
        <div class="source-code-inner">
          {lines.map((line, index) => {
            const lineNum = index + 1;
            const hits = fileCoverage[lineNum.toString()];

            let statusClass = "";
            if (hits !== undefined) {
              statusClass = hits > 0 ? "covered" : "uncovered";
            }

            const isDelta = deltaLines.includes(lineNum);

            return (
              <div class={`line ${statusClass}`}>
                <span class="line-number">{lineNum}</span>
                {isDelta ? (
                  <span class="line-change-marker" title="Added in this PR">
                    +
                  </span>
                ) : (
                  <span class="line-change-marker"></span>
                )}
                <code class="language-rust content">{line || " "}</code>
                {hits !== undefined && hits > 0 && (
                  <span class="hit-count" title={`${hits} hits`}>
                    {hits}x
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </Layout>,
  );
});

export default ui;
