# FraudShield — Fraud Detection Dashboard

A React + Vite dashboard with an in-browser Logistic Regression training demo and a Node.js/Express authentication API.

## Requirements

- Node.js 20 or newer (LTS recommended)
- npm

## Run locally

1. Extract the ZIP and open the `fraudshield` folder in VS Code.
2. Open a terminal in this folder and install dependencies:

   ```bash
   npm install
   ```

3. Start the backend in one terminal:

   ```bash
   npm run server
   ```

4. Start the frontend in a second terminal:

   ```bash
   npm run dev
   ```

5. Open the Vite URL printed in the terminal, normally `http://localhost:5173`.
6. Select **Create an account**, register with an email and a unique password of at least 10 characters, then sign in.

The Vite development server proxies `/api` requests to the Express server on port 3001. Keep both terminals running while using the app.

## Authentication/backend included

- Account registration and login through the Express API.
- Passwords hashed with Node.js `scrypt` and a unique random salt; plaintext passwords are never written to the data store.
- Random session tokens stored as hashes server-side and delivered in `HttpOnly`, `SameSite=Strict` cookies; cookies are marked `Secure` when `NODE_ENV=production`.
- Eight-hour sessions, logout/revocation, authenticated profile updates, server-side validation, generic login failures, request-size limits, security headers, same-origin mutation checks, and authentication rate limiting.
- User records are stored in `data/store.json`, created on first run. This simple JSON store is intended for a single-machine internship demo, not concurrent production deployment. Keep the data file private and out of version control.

## Dashboard functionality

- Sidebar navigation for Overview, Dataset Explorer, Data Preprocessing, Classifier Models, Train & Tune, Model Evaluation, Fraud Prediction, Reports, and Settings.
- Responsive layout and light/dark theme.
- CSV upload, parsing, column detection, and data preview.
- Logistic Regression trained in-browser from numeric features in a labelled CSV, with held-out precision, recall, F1, and ROC-AUC.
- Prediction page uses the fitted model after training.
- CSV report export; illustrative comparison chart values are labelled as illustrative.

## Build check

```bash
npm run build
```

## Deployment

### Option 1: Vercel (Recommended)
1. Push this repository to GitHub.
2. In Vercel, import the repository.
3. Vercel automatically detects the Vite frontend and routes `/api/*` requests through the serverless function in `api/index.js` (configured via `vercel.json`).
4. Build command: `npm run build`, output directory: `dist`.

### Option 2: Render / Railway / Node.js Host
1. Set the build command to `npm install && npm run build`.
2. Set the start command to `npm start`.
3. The Express server (`server.js`) automatically serves the compiled frontend from `dist` and powers the `/api` backend on the assigned `$PORT`.

### Option 3: Netlify or GitHub Pages (Static Hosting)
- Build command: `npm run build`
- Publish directory: `dist`
- If you deploy to a purely static host without Node.js backend support, you can click **"Continue to Demo Workspace"** on the login screen to explore the complete interactive dashboard, CSV uploads, in-browser model training, and predictions without needing a live backend server.

## Important limitations

This is an internship/demo application, not a production banking service. The dashboard's model trains in the browser; it is not a deployed fraud-detection service, and demo/reference chart values remain illustrative. Do not upload real card numbers, CVVs, or sensitive customer records. The authentication backend demonstrates core safeguards, but before public deployment you should replace the JSON file store with a managed database, use HTTPS, configure secrets and backups, add email verification/password reset, audit logging, and have the app security-reviewed. Do not reuse your banking or personal email password.

