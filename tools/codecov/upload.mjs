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

import fs from "fs/promises";
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";

const execAsync = promisify(exec);

/**
 * Executes a shell command and returns the trimmed standard output.
 */
async function runCmd(cmd, cwd) {
  try {
    const { stdout } = await execAsync(cmd, { cwd });
    return stdout.trim();
  } catch (err) {
    console.error(`Failed to execute command: ${cmd}`);
    throw err;
  }
}

/**
 * Retrieves necessary Git information for the current repository.
 */
async function getGitInfo(customBranch, prBase) {
  const cwd = process.cwd();
  const commit_sha = await runCmd("git rev-parse HEAD", cwd);

  let parent_sha = null;
  try {
    if (prBase) {
      parent_sha = await runCmd(`git rev-parse ${prBase}`, cwd);
    } else {
      parent_sha = await runCmd("git rev-parse HEAD~1", cwd);
    }
  } catch (e) {
    // If there is no parent (first commit), this is expected.
  }

  let branch =
    customBranch || process.env.GITHUB_HEAD_REF || process.env.GITHUB_REF_NAME;
  if (!branch) {
    branch = await runCmd("git rev-parse --abbrev-ref HEAD", cwd);
    if (branch === "HEAD") {
      try {
        const remoteBranches = await runCmd(
          "git branch -r --contains HEAD",
          cwd,
        );
        const branches = remoteBranches
          .split("\n")
          .map((b) => b.trim())
          .filter((b) => b && !b.includes("->"));
        if (branches.length > 0) {
          branch = branches[0].replace(/^[^\/]+\//, "");
        }
      } catch (err) {}
    }
  }

  const repoRoot = await runCmd("git rev-parse --show-toplevel", cwd);
  const commit_timestamp = await runCmd("git show -s --format=%cI HEAD", cwd);

  let gitStatusMap = {};
  try {
    const diffTreeCmd =
      prBase && parent_sha
        ? `git diff-tree --no-commit-id --name-status -r ${parent_sha} HEAD`
        : "git diff-tree --no-commit-id --name-status -r HEAD";
    const nameStatus = await runCmd(diffTreeCmd, cwd);
    const statusLines = nameStatus.split("\n");
    for (const statusLine of statusLines) {
      if (!statusLine.trim()) continue;
      const parts = statusLine.trim().split(/\s+/);
      if (parts.length >= 2) {
        const status = parts[0][0]; // 'M', 'A', 'D', 'R', etc.
        const filePath = parts[parts.length - 1];
        gitStatusMap[filePath] = status;
      }
    }
  } catch (err) {
    // Ignore errors if diff-tree fails
  }

  let gitLineDiffs = {};
  if (parent_sha) {
    try {
      const diffOutput = await runCmd(`git diff -U0 ${parent_sha} HEAD`, cwd);

      let currentFile = null;
      for (const line of diffOutput.split("\n")) {
        if (line.startsWith("+++ b/")) {
          currentFile = line.substring(6).trim();
          gitLineDiffs[currentFile] = [];
        } else if (line.startsWith("@@ ") && currentFile) {
          // Format: @@ -old_line,old_count +new_line,new_count @@
          const match = line.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
          if (match) {
            const startLine = parseInt(match[1], 10);
            const count = match[2] === undefined ? 1 : parseInt(match[2], 10);

            for (let i = 0; i < count; i++) {
              gitLineDiffs[currentFile].push(startLine + i);
            }
          }
        }
      }
    } catch (err) {
      console.error(`Failed to execute git diff: ${err}`);
    }
  }

  return {
    commit_sha,
    parent_sha,
    branch,
    repoRoot,
    commit_timestamp,
    gitStatusMap,
    gitLineDiffs,
  };
}

/**
 * Parses an LCOV coverage file into a JSON format expected by the worker API.
 * Format: { "src/main.rs": { "1": 1, "2": 0 } }
 */
async function parseLcov(
  filePath,
  repoRoot,
  lcovBase,
  gitStatusMap,
  gitLineDiffs,
) {
  let content;
  try {
    content = await fs.readFile(filePath, "utf-8");
  } catch (err) {
    console.error(`Error reading coverage file at ${filePath}`);
    console.error("Make sure you have generated the coverage report first.");
    process.exit(1);
  }

  const lines = content.split("\n");
  const report = {};

  let currentFile = null;
  let totalLines = 0;
  let coveredLines = 0;
  let fileTotalLines = 0;
  let fileCoveredLines = 0;

  let totalDeltaLines = 0;
  let coveredDeltaLines = 0;

  for (const line of lines) {
    if (line.startsWith("SF:")) {
      // Extract the source file path
      let sf = line.substring(3).trim();

      if (lcovBase && sf.startsWith(lcovBase)) {
        sf = path.relative(lcovBase, sf);
      } else if (path.isAbsolute(sf) && sf.startsWith(repoRoot)) {
        sf = path.relative(repoRoot, sf);
      }

      try {
        await fs.access(path.resolve(process.cwd(), sf));
      } catch (err) {
        console.error(
          `\n[!] Error: File path in lcov does not match any source file in working directory.`,
        );
        console.error(`    LCOV path: ${line.substring(3).trim()}`);
        console.error(`    Resolved relative path: ${sf}`);
        console.error(
          `    Expected full path: ${path.resolve(process.cwd(), sf)}`,
        );
        console.error(
          `    Try using --lcov-base <path> to strip the prefix used in the lcov file.`,
        );
        process.exit(1);
      }

      currentFile = sf;
      report[currentFile] = {};
      fileTotalLines = 0;
      fileCoveredLines = 0;
    } else if (line.startsWith("DA:") && currentFile) {
      // Parse execution data: DA:<line_number>,<execution_count>[,<checksum>]
      const parts = line.substring(3).split(",");
      const lineNum = parts[0];
      const hits = parseInt(parts[1], 10);

      report[currentFile][lineNum] = hits;

      const isDelta =
        gitLineDiffs &&
        gitLineDiffs[currentFile] &&
        gitLineDiffs[currentFile].includes(parseInt(lineNum, 10));

      if (isDelta) {
        if (!report[currentFile].delta_lines) {
          report[currentFile].delta_lines = [];
        }
        report[currentFile].delta_lines.push(parseInt(lineNum, 10));
        totalDeltaLines++;
        if (!report[currentFile]._fileTotalDelta)
          report[currentFile]._fileTotalDelta = 0;
        if (!report[currentFile]._fileCoveredDelta)
          report[currentFile]._fileCoveredDelta = 0;
        report[currentFile]._fileTotalDelta++;
      }

      totalLines++;
      fileTotalLines++;
      if (hits > 0) {
        coveredLines++;
        fileCoveredLines++;
        if (isDelta) {
          coveredDeltaLines++;
          report[currentFile]._fileCoveredDelta++;
        }
      }
    } else if (line === "end_of_record") {
      if (currentFile) {
        report[currentFile].coverage_pct =
          fileTotalLines === 0 ? 0 : (fileCoveredLines / fileTotalLines) * 100;
        if (gitStatusMap && gitStatusMap[currentFile]) {
          report[currentFile].status = gitStatusMap[currentFile];
        }

        if (report[currentFile]._fileTotalDelta !== undefined) {
          report[currentFile].delta_coverage_pct =
            report[currentFile]._fileTotalDelta === 0
              ? 0
              : (report[currentFile]._fileCoveredDelta /
                  report[currentFile]._fileTotalDelta) *
                100;
          delete report[currentFile]._fileTotalDelta;
          delete report[currentFile]._fileCoveredDelta;
        }

        currentFile = null;
      }
    }
  }

  const coverage_pct = totalLines === 0 ? 0 : (coveredLines / totalLines) * 100;
  const delta_coverage_pct =
    totalDeltaLines === 0 ? null : (coveredDeltaLines / totalDeltaLines) * 100;

  return { report, coverage_pct, delta_coverage_pct };
}

async function printAndPostComment(
  prNumber,
  commit_sha,
  coverage_pct,
  delta_coverage_pct,
  report,
  apiUrl,
) {
  const ghToken = process.env.GITHUB_TOKEN;
  const ghRepo = process.env.GITHUB_REPOSITORY;

  // Derive dashboard base URL from apiUrl
  const dashboardUrl = apiUrl.replace(/\/api\/upload\/?$/, "");
  const isPr = prNumber !== null && prNumber !== undefined;
  const linkBase = isPr
    ? `${dashboardUrl}/pr/${prNumber}`
    : `${dashboardUrl}/commit/${commit_sha}`;

  let body = `<!-- codecov-worker-report -->\n### Code Coverage Report\n\n`;
  body += `**Overall Coverage:** ${coverage_pct.toFixed(2)}%\n`;
  if (delta_coverage_pct !== null && delta_coverage_pct !== undefined) {
    body += `**Patch Coverage:** ${delta_coverage_pct.toFixed(2)}%\n`;
  }
  body += `\n[View Detailed Report on Dashboard](${linkBase})\n\n`;

  // Get changed files
  const touchedFiles = Object.entries(report)
    .filter(([_, data]) => data.status)
    .sort((a, b) => a[0].localeCompare(b[0]));

  if (touchedFiles.length > 0) {
    body += `<details>\n<summary>Changed Files Coverage</summary>\n\n`;
    body += `| File | Coverage | Patch Coverage |\n`;
    body += `|:---|---:|---:|\n`;

    for (const [file, data] of touchedFiles) {
      const covPct =
        data.coverage_pct !== undefined
          ? `${data.coverage_pct.toFixed(2)}%`
          : "N/A";
      const deltaPct =
        data.delta_coverage_pct !== undefined
          ? `${data.delta_coverage_pct.toFixed(2)}%`
          : "-";
      body += `| [${file}](${linkBase}/file/${file}) | ${covPct} | ${deltaPct} |\n`;
    }
    body += `\n</details>\n`;
  }

  console.log(
    `\n      --- Markdown Comment ---\n${body}      ------------------------\n`,
  );

  if (!isPr) {
    return;
  }

  if (!ghToken || !ghRepo) {
    console.log(
      "      Skipping GitHub comment: GITHUB_TOKEN or GITHUB_REPOSITORY not set.",
    );
    return;
  }

  const commentsEndpoint = `https://api.github.com/repos/${ghRepo}/issues/${prNumber}/comments`;

  try {
    const getRes = await fetch(commentsEndpoint, {
      headers: {
        Authorization: `Bearer ${ghToken}`,
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "codecov-worker",
      },
    });

    let existingCommentId = null;
    if (getRes.ok) {
      const comments = await getRes.json();
      const existing = comments.find(
        (c) => c.body && c.body.includes("<!-- codecov-worker-report -->"),
      );
      if (existing) {
        existingCommentId = existing.id;
      }
    }

    const endpoint = existingCommentId
      ? `https://api.github.com/repos/${ghRepo}/issues/comments/${existingCommentId}`
      : commentsEndpoint;
    const method = existingCommentId ? "PATCH" : "POST";

    const res = await fetch(endpoint, {
      method,
      headers: {
        Authorization: `Bearer ${ghToken}`,
        Accept: "application/vnd.github.v3+json",
        "Content-Type": "application/json",
        "User-Agent": "codecov-worker",
      },
      body: JSON.stringify({ body }),
    });

    if (res.ok) {
      console.log(
        `      Successfully ${
          existingCommentId ? "updated" : "posted"
        } comment on PR #${prNumber}`,
      );
    } else {
      console.error(
        `      Failed to post PR comment: ${res.status} ${res.statusText}`,
      );
      const errText = await res.text();
      console.error(`      Details: ${errText}`);
    }
  } catch (err) {
    console.error(`      Error posting PR comment: ${err.message}`);
  }
}

async function main() {
  let lcovPath = null;
  let lcovBase = null;
  let customBranch = null;
  let prNumber = null;
  let prBase = null;
  const args = process.argv.slice(2);

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--lcov-base") {
      lcovBase = args[i + 1];
      i++;
    } else if (args[i] === "--branch") {
      customBranch = args[i + 1];
      i++;
    } else if (args[i] === "--pr") {
      prNumber = parseInt(args[i + 1], 10);
      i++;
    } else if (args[i] === "--pr-base") {
      prBase = args[i + 1];
      i++;
    } else {
      lcovPath = args[i];
    }
  }
  if (!lcovPath) lcovPath = "../alioth/lcov.info";

  const apiUrl = process.env.CODECOV_URL || "http://localhost:8787/api/upload";
  const apiToken = process.env.CODECOV_TOKEN;

  console.log(`[1/4] Reading Git information...`);
  const {
    commit_sha,
    parent_sha,
    branch,
    repoRoot,
    commit_timestamp,
    gitStatusMap,
    gitLineDiffs,
  } = await getGitInfo(customBranch, prBase);
  console.log(`      Commit: ${commit_sha}`);
  console.log(`      Branch: ${branch}`);
  console.log(`      Root:   ${repoRoot}`);
  console.log(`      Date:   ${commit_timestamp}`);
  if (lcovBase) {
    console.log(`      LCOV Base: ${lcovBase}`);
  }
  if (prNumber) {
    console.log(`      PR Number: ${prNumber}`);
    console.log(`      PR Base:   ${parent_sha}`);
  }

  console.log(`\n[2/4] Parsing coverage from ${lcovPath}...`);
  const { report, coverage_pct, delta_coverage_pct } = await parseLcov(
    lcovPath,
    repoRoot,
    lcovBase,
    gitStatusMap,
    gitLineDiffs,
  );
  console.log(`      Files tracked: ${Object.keys(report).length}`);
  console.log(`      Overall coverage: ${coverage_pct.toFixed(2)}%`);
  if (delta_coverage_pct !== null) {
    console.log(`      Delta coverage:   ${delta_coverage_pct.toFixed(2)}%`);
  }

  const payload = {
    commit_sha,
    branch,
    commit_timestamp,
    coverage_pct,
    delta_coverage_pct,
    report,
  };

  if (prNumber) {
    payload.pr_number = prNumber;
    payload.base_sha = parent_sha;
  }

  console.log(`\n[3/4] Uploading coverage data...`);
  console.log(`      Endpoint: ${apiUrl}`);

  const headers = { "Content-Type": "application/json" };
  if (apiToken) {
    headers["Authorization"] = `Bearer ${apiToken}`;
  } else {
    console.warn(
      `      Warning: CODECOV_TOKEN environment variable is not set. The upload may fail if the server requires authentication.`,
    );
  }

  try {
    const res = await fetch(apiUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error(
        `\n[!] Failed to upload coverage: ${res.status} ${res.statusText}`,
      );
      console.error(`    Details: ${errText}`);
      process.exit(1);
    }

    const data = await res.json();
    console.log(`\n[4/4] Upload successful!`);
    console.log(`      Response:`, data);

    console.log(`\n[+] Generating Markdown Report...`);
    await printAndPostComment(
      prNumber,
      commit_sha,
      coverage_pct,
      delta_coverage_pct,
      report,
      apiUrl,
    );
  } catch (err) {
    console.error(`\n[!] Network error while uploading coverage:`);
    console.error(err.message);
    console.error(
      `\nMake sure your Cloudflare Worker is running locally (wrangler dev) or provide a valid CODECOV_URL.`,
    );
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("\n[!] An unexpected error occurred:");
  console.error(err);
  process.exit(1);
});
