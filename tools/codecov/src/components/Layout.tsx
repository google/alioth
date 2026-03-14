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

import { html } from "hono/html";

type LayoutProps = {
  children: any;
  title: string;
  projectName: string;
};

export const Layout = (props: LayoutProps) => html`
  <!DOCTYPE html>
  <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>${props.title} - ${props.projectName} Codecov</title>
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
      <link
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
        rel="stylesheet"
      />
      <link
        href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism.min.css"
        rel="stylesheet"
      />
      <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-rust.min.js"></script>
      <style>
        :root {
          --bg-color: #f8fafc;
          --surface-color: #ffffff;
          --text-primary: #0f172a;
          --text-secondary: #475569;
          --border-color: #e2e8f0;
          --primary-color: #3b82f6;
          --primary-hover: #2563eb;
          --covered-bg: #dcfce7;
          --covered-text: #166534;
          --uncovered-bg: #fee2e2;
          --uncovered-text: #991b1b;
          --high-cov: #10b981;
          --med-cov: #f59e0b;
          --low-cov: #ef4444;
          --radius: 8px;
          --shadow:
            0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
        }

        body {
          font-family:
            "Inter",
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            Roboto,
            Helvetica,
            Arial,
            sans-serif;
          margin: 0;
          padding: 0;
          background-color: var(--bg-color);
          color: var(--text-primary);
          line-height: 1.6;
          display: flex;
          flex-direction: column;
          min-height: 100vh;
          -webkit-font-smoothing: antialiased;
        }

        main {
          flex: 1;
          max-width: 1200px;
          margin: 0 auto;
          width: 100%;
          padding: 0 2rem;
          box-sizing: border-box;
        }

        header {
          background-color: var(--surface-color);
          box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);
          margin-bottom: 2rem;
          border-bottom: 1px solid var(--border-color);
        }

        .header-inner {
          max-width: 1200px;
          margin: 0 auto;
          padding: 1.25rem 2rem;
          width: 100%;
          box-sizing: border-box;
        }

        header h1 {
          margin: 0;
          font-size: 1.25rem;
          font-weight: 600;
          letter-spacing: -0.025em;
        }

        header a {
          color: var(--text-primary);
          text-decoration: none;
        }

        header a:hover {
          color: var(--primary-hover);
        }

        a {
          color: var(--primary-color);
          text-decoration: none;
          transition: color 0.15s ease;
        }

        a:hover {
          color: var(--primary-hover);
          text-decoration: underline;
        }

        h2,
        h3 {
          color: var(--text-primary);
          letter-spacing: -0.025em;
          margin-top: 2rem;
          margin-bottom: 1rem;
          font-weight: 600;
        }

        .table-responsive {
          background: var(--surface-color);
          border-radius: var(--radius);
          box-shadow: var(--shadow);
          overflow-x: auto;
          -webkit-overflow-scrolling: touch;
          border: 1px solid var(--border-color);
          margin-bottom: 2rem;
          width: 100%;
        }

        table {
          width: 100%;
          border-collapse: collapse;
        }

        th,
        td {
          text-align: left;
          padding: 12px 16px;
          white-space: nowrap;
          border-bottom: 1px solid var(--border-color);
        }

        th.right-align,
        td.right-align {
          text-align: right;
        }

        th {
          background-color: #f8fafc;
          font-weight: 600;
          color: var(--text-secondary);
          text-transform: uppercase;
          font-size: 0.75rem;
          letter-spacing: 0.05em;
        }

        tbody tr:last-child td {
          border-bottom: none;
        }

        tbody tr:nth-child(even) {
          background-color: #f8fafc;
        }

        .source-code {
          background: var(--surface-color);
          border: 1px solid var(--border-color);
          border-radius: var(--radius);
          box-shadow: var(--shadow);
          font-family:
            "JetBrains Mono", ui-monospace, SFMono-Regular, Consolas, monospace;
          font-size: 13px;
          overflow-x: auto;
          -webkit-overflow-scrolling: touch;
          padding: 16px 0;
          margin-top: 1rem;
          margin-bottom: 2rem;
        }

        .source-code-inner {
          display: inline-block;
          min-width: 100%;
        }

        .line {
          display: flex;
          white-space: pre;
          min-height: 22px;
          align-items: center;
        }

        .line-number {
          width: 50px;
          min-width: 50px;
          text-align: right;
          color: var(--text-secondary);
          padding-right: 15px;
          user-select: none;
          border-right: 1px solid var(--border-color);
          margin-right: 15px;
        }

        .line-change-marker {
          width: 15px;
          min-width: 15px;
          color: var(--high-cov);
          font-weight: bold;
          text-align: center;
          user-select: none;
          margin-right: 5px;
        }

        .content {
          padding-right: 10px;
        }

        .hit-count {
          margin-left: auto;
          margin-right: 15px;
          padding: 2px 8px;
          border-radius: 999px;
          font-size: 11px;
          font-weight: 600;
          user-select: none;
        }

        .covered .hit-count {
          background-color: var(--covered-bg);
          color: var(--covered-text);
        }

        .uncovered .hit-count {
          background-color: var(--uncovered-bg);
          color: var(--uncovered-text);
        }

        code.content[class*="language-"] {
          background: transparent !important;
          text-shadow: none !important;
          padding: 0 !important;
          margin: 0 !important;
          color: inherit;
          white-space: pre;
        }

        /* Coverage Colors */
        .covered {
          background-color: var(--covered-bg);
        }

        .uncovered {
          background-color: var(--uncovered-bg);
        }

        .breadcrumb {
          font-size: 0.875rem;
          margin-bottom: 1.5rem;
          color: var(--text-secondary);
          background: var(--surface-color);
          padding: 0.75rem 1rem;
          border-radius: var(--radius);
          border: 1px solid var(--border-color);
          box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);
        }

        .pct-high {
          color: var(--high-cov);
          font-weight: 600;
        }
        .pct-medium {
          color: var(--med-cov);
          font-weight: 600;
        }
        .pct-low {
          color: var(--low-cov);
          font-weight: 600;
        }

        /* Mobile Responsive Adjustments */
        @media (max-width: 768px) {
          main {
            padding: 0 12px;
          }
          .header-inner {
            padding: 1rem 12px;
          }
          .footer-inner {
            padding: 1.5rem 12px;
          }
          th,
          td {
            padding: 10px 12px;
          }
          .line-number {
            min-width: 35px;
            width: 35px;
            padding-right: 8px;
            margin-right: 8px;
            font-size: 12px;
          }
          .source-code {
            font-size: 12px;
            padding: 12px 0;
          }
          h1 {
            font-size: 1.25rem;
          }
          h2 {
            font-size: 1.125rem;
          }
          h3 {
            font-size: 1rem;
          }
          .breadcrumb {
            font-size: 12px;
            overflow-wrap: break-word;
            padding: 0.5rem 0.75rem;
          }
        }

        .site-footer {
          margin-top: auto;
          background-color: var(--surface-color);
          border-top: 1px solid var(--border-color);
          color: var(--text-secondary);
        }

        .footer-inner {
          max-width: 1200px;
          margin: 0 auto;
          padding: 2rem;
          width: 100%;
          box-sizing: border-box;
          text-align: center;
          font-size: 0.875rem;
        }

        .site-footer a {
          color: var(--text-secondary);
          font-weight: 500;
        }

        .site-footer a:hover {
          color: var(--primary-hover);
        }
      </style>
    </head>
    <body>
      <header>
        <div class="header-inner">
          <h1><a href="/">${props.projectName} Code Coverage</a></h1>
        </div>
      </header>
      <main>${props.children}</main>
      <footer class="site-footer">
        <div class="footer-inner">
          By
          <a
            href="https://github.com/Lencerf"
            target="_blank"
            rel="noopener noreferrer"
            >Lencerf</a
          >
          with Gemini
        </div>
      </footer>
    </body>
  </html>
`;
