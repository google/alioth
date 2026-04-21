# Alioth Code Coverage Dashboard

This project is a lightweight, Coveralls-style code coverage dashboard. It is built using the [Hono](https://hono.dev) framework and runs on **Cloudflare Workers**. It can be configured to serve any GitHub repository via `wrangler.toml`.

To remain within edge execution limits and keep storage costs low, this app uses:
- **Cloudflare D1 (SQLite)**: To store lightweight metadata (commit SHA, branch, overall coverage %).
- **Cloudflare R2 (Blob Storage)**: To store parsed coverage mappings as JSON.
- **GitHub Raw API**: To dynamically fetch source code on demand, rather than storing massive source files in a database.

## Prerequisites

- Node.js (v18+)
- A Cloudflare account
- `wrangler` CLI installed globally or via `npx`

## Setup & Configuration

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Create the D1 Database:**
   ```bash
   npx wrangler d1 create alioth-codecov-db
   ```
   *Take note of the `database_id` returned by this command.*

3. **Update `wrangler.toml`:**
   Open `wrangler.toml` and replace `REPLACE_WITH_YOUR_D1_DATABASE_ID` with the actual ID you just generated.

4. **Create the R2 Bucket:**
   ```bash
   npx wrangler r2 bucket create alioth-codecov-reports
   ```

5. **Initialize the Database Schema:**
   Run the schema against your production D1 database:
   ```bash
   npx wrangler d1 execute alioth-codecov-db --remote --file=./schema.sql
   ```

## Local Development

To run the worker locally, you first need to initialize the local SQLite database simulation:

```bash
# Initialize local DB
npx wrangler d1 execute alioth-codecov-db --local --file=./schema.sql

# Start the development server
npm run dev
```

The app will be available at `http://localhost:8787`.

## Securing the API (Authentication)

To prevent unauthorized uploads to your dashboard, you should set a secret token. Both the worker and the upload script will use this to verify the payload.

1. **Generate a random token** (e.g., `openssl rand -hex 32`).
2. **Set the token in Cloudflare Secrets:**
   ```bash
   npx wrangler secret put CODECOV_TOKEN
   ```
   *(Paste your token when prompted)*
3. **Set the token for local development:** Create a `.dev.vars` file in the `codecov` directory:
   ```env
   CODECOV_TOKEN=your_local_secret_token
   ```

## Deployment

Deploy the worker to your Cloudflare account:

```bash
npm run deploy
```

Once deployed, you will receive a `*.workers.dev` URL (or your custom domain) where the dashboard is hosted.

## Uploading Coverage Reports

A Node.js script (`upload.mjs`) is provided to parse `lcov.info` files and upload them to the worker. 

This script extracts git metadata (commit SHA, branch) directly from the local git repository and converts the LCOV file into an optimized JSON payload before sending it to the API.

### Usage

```bash
# Export the URL of your deployed worker (or use localhost for local testing)
export CODECOV_URL="https://your-worker-url.workers.dev/api/upload"

# Export the authentication token you created
export CODECOV_TOKEN="your_secret_token"

# Run the upload script from the root of your repository
node tools/codecov/upload.mjs ./lcov.info
```

### CI/CD Integration (GitHub Actions)
In your GitHub Actions workflow, after running tests and generating an `lcov` report, you can use a unified step to automatically push coverage data to your dashboard for both regular commits and pull requests:

```yaml
- name: Upload Coverage
  run: |
    PR_ARGS=""
    if [ "${{ github.event_name }}" = "pull_request" ]; then
      PR_ARGS="--pr ${{ github.event.pull_request.number }} --pr-base ${{ github.event.pull_request.base.sha }}"
    fi
    node tools/codecov/upload.mjs ./lcov.info $PR_ARGS
  env:
    CODECOV_URL: ${{ vars.CODECOV_URL }}
    CODECOV_TOKEN: ${{ secrets.CODECOV_TOKEN }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Shields.io Badge

You can embed a dynamic code coverage badge in your repository's `README.md` using Shields.io. The badge will automatically turn green (>=80%), yellow (>=60%), or red depending on the coverage of your `main` branch.

```md
![Coverage](https://img.shields.io/endpoint?url=https://your-worker-url.workers.dev/api/badge)
```

To fetch the badge for a specific branch, append `?branch=branch-name` to the endpoint URL:

```md
![Coverage](https://img.shields.io/endpoint?url=https://your-worker-url.workers.dev/api/badge?branch=feature/test)
```
