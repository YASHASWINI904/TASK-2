# FraudShield verification status

## Checks completed in this environment

- ZIP archive extracted successfully.
- `server.js` passes Node.js syntax validation (`node --check server.js`).
- Reviewed the frontend authentication flow and API endpoints in source.
- Corrected the profile editor's helper text so it accurately states that changes are saved through the API.

## Checks not completed

- `npm install` could not complete because this environment could not resolve `registry.npmjs.org` (`EAI_AGAIN`). Therefore, `npm run build` could not be run here.
- Browser end-to-end checks (register, login, reload/session persistence, profile update, logout, CSV training and prediction) could not be executed without installed dependencies and a running browser session.

## Run these checks on your computer

1. Install Node.js 20 or newer.
2. In this folder, run `npm install`.
3. Run `npm run build`; fix any errors before submission.
4. Start terminal 1 with `npm run server`.
5. Start terminal 2 with `npm run dev`.
6. In the browser, test registration, sign-in, refresh (session should persist), profile update, sign-out, CSV upload, model training, prediction and report export.

This is an educational internship demo. Do not use real payment-card data or present it as a production banking service.
