export type Bindings = {
  DB: D1Database;
  COVERAGE_BUCKET: R2Bucket;
  CODECOV_TOKEN?: string;
  GITHUB_REPO?: string;
  PROJECT_NAME?: string;
  RETENTION_DAYS?: number;
};

export type TreeNode = {
  name: string;
  type: "file" | "dir";
  path: string;
  children: Record<string, TreeNode>;
  totalLines: number;
  coveredLines: number;
  coverage_pct?: number;
  delta_coverage_pct?: number;
  status?: string;
};

export type FlatNode = {
  name: string;
  type: "file" | "dir";
  path: string;
  depth: number;
  coverage_pct?: number;
  delta_coverage_pct?: number;
  status?: string;
};
