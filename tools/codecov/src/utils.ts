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

import { TreeNode, FlatNode } from "./types.ts";

export function formatDate(dateInput: string | number | Date) {
  const d = new Date(dateInput);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}, ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function buildTree(coverageData: Record<string, any>): TreeNode {
  const root: TreeNode = {
    name: "root",
    type: "dir",
    path: "",
    children: {},
    totalLines: 0,
    coveredLines: 0,
  };

  for (const [filePath, fileData] of Object.entries(coverageData)) {
    const parts = filePath.split("/");
    let current = root;

    let fileTotalLines = 0;
    let fileCoveredLines = 0;
    let status = fileData.status as string | undefined;
    let delta_coverage_pct = fileData.delta_coverage_pct as number | undefined;

    for (const [key, hits] of Object.entries(fileData)) {
      if (
        key !== "coverage_pct" &&
        key !== "status" &&
        key !== "delta_coverage_pct" &&
        key !== "delta_lines"
      ) {
        fileTotalLines++;
        if ((hits as number) > 0) fileCoveredLines++;
      }
    }

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isFile = i === parts.length - 1;

      if (!current.children[part]) {
        current.children[part] = {
          name: part,
          type: isFile ? "file" : "dir",
          path: isFile ? filePath : "",
          children: {},
          totalLines: 0,
          coveredLines: 0,
        };
      }

      if (isFile && status) {
        current.children[part].status = status;
      }
      if (isFile && delta_coverage_pct !== undefined) {
        current.children[part].delta_coverage_pct = delta_coverage_pct;
      }

      current.children[part].totalLines += fileTotalLines;
      current.children[part].coveredLines += fileCoveredLines;

      if (current.children[part].totalLines > 0) {
        current.children[part].coverage_pct =
          (current.children[part].coveredLines /
            current.children[part].totalLines) *
          100;
      }

      current = current.children[part];
    }

    root.totalLines += fileTotalLines;
    root.coveredLines += fileCoveredLines;
    if (root.totalLines > 0) {
      root.coverage_pct = (root.coveredLines / root.totalLines) * 100;
    }
  }

  return root;
}

export function flattenTree(node: TreeNode, depth: number = 0): FlatNode[] {
  let result: FlatNode[] = [];
  const children = Object.values(node.children).sort((a, b) => {
    if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  for (const child of children) {
    result.push({
      name: child.name,
      type: child.type,
      path: child.path,
      depth,
      coverage_pct: child.coverage_pct,
      delta_coverage_pct: child.delta_coverage_pct,
      status: child.status,
    });
    if (child.type === "dir") {
      result = result.concat(flattenTree(child, depth + 1));
    }
  }
  return result;
}
