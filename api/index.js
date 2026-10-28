import app, { loadStore } from '../server.js';

let ready = false;
export default async function handler(req, res) {
  if (!ready) {
    await loadStore();
    ready = true;
  }
  return app(req, res);
}
