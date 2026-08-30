'use strict';

// Gates /api/scan/* behind a shared key when API_KEY is set in the environment.
// Browsers can't send custom headers on EventSource, so the key is also
// accepted as a query param for the SSE endpoint.
function requireApiKey(req, res, next) {
  const configured = process.env.API_KEY;
  if (!configured) return next();

  const provided = req.header('x-api-key') || req.query.apiKey;
  if (provided !== configured) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  next();
}

module.exports = { requireApiKey };
