-- Copyright 2026 Google LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

DROP TABLE IF EXISTS coverage_reports;

CREATE TABLE coverage_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    commit_sha TEXT NOT NULL UNIQUE,
    branch TEXT NOT NULL,
    coverage_pct REAL NOT NULL,
    delta_coverage_pct REAL,
    commit_timestamp DATETIME NOT NULL
);

CREATE INDEX idx_coverage_reports_commit_sha ON coverage_reports(commit_sha);
CREATE INDEX idx_coverage_reports_branch ON coverage_reports(branch);
CREATE INDEX idx_coverage_reports_commit_timestamp ON coverage_reports(commit_timestamp DESC);

DROP TABLE IF EXISTS pr_reports;

CREATE TABLE pr_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pr_number INTEGER NOT NULL UNIQUE,
    head_sha TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    coverage_pct REAL NOT NULL,
    delta_coverage_pct REAL,
    commit_timestamp DATETIME NOT NULL
);

CREATE INDEX idx_pr_reports_pr_number ON pr_reports(pr_number);
CREATE INDEX idx_pr_reports_commit_timestamp ON pr_reports(commit_timestamp DESC);
