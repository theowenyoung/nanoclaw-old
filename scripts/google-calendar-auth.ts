#!/usr/bin/env npx tsx
/**
 * Google Calendar OAuth Setup for NanoClaw
 *
 * Handles the OAuth flow directly — prints the auth URL for you to visit,
 * starts a local server to catch the callback, and saves the tokens.
 *
 * Prerequisites:
 *   1. Create a Google Cloud project and enable Google Calendar API
 *   2. Create OAuth 2.0 credentials (Desktop app type)
 *   3. Add http://localhost:3500/oauth2callback as an authorized redirect URI
 *   4. Download credentials.json and place it at data/google-calendar/credentials.json
 *
 * Usage:
 *   npx tsx scripts/google-calendar-auth.ts
 */

import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import path from 'path';
import { URL } from 'url';

const DATA_DIR = path.join(process.cwd(), 'data', 'google-calendar');
const CREDENTIALS_PATH = path.join(DATA_DIR, 'credentials.json');
const TOKENS_PATH = path.join(DATA_DIR, 'tokens.json');

const SCOPE = 'https://www.googleapis.com/auth/calendar';
const PORT = 3500;
const REDIRECT_URI = `http://localhost:${PORT}/oauth2callback`;

interface Credentials {
  installed?: {
    client_id: string;
    client_secret: string;
    redirect_uris?: string[];
  };
  client_id?: string;
  client_secret?: string;
}

function loadCredentials(): { clientId: string; clientSecret: string } {
  const raw: Credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf-8'));
  if (raw.installed) {
    return { clientId: raw.installed.client_id, clientSecret: raw.installed.client_secret };
  }
  if (raw.client_id && raw.client_secret) {
    return { clientId: raw.client_id, clientSecret: raw.client_secret };
  }
  throw new Error('Invalid credentials.json format — expected "installed" or flat format');
}

function base64url(buf: Buffer): string {
  return buf.toString('base64url');
}

async function exchangeCode(
  code: string,
  clientId: string,
  clientSecret: string,
  codeVerifier: string,
): Promise<Record<string, unknown>> {
  const body = new URLSearchParams({
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: REDIRECT_URI,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier,
  });

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed (${res.status}): ${text}`);
  }

  return (await res.json()) as Record<string, unknown>;
}

async function main(): Promise<void> {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  if (!fs.existsSync(CREDENTIALS_PATH)) {
    console.error('\nMissing credentials file!\n');
    console.error('Please follow these steps:\n');
    console.error('1. Go to https://console.cloud.google.com/apis/credentials');
    console.error('2. Create a project (or select existing)');
    console.error('3. Enable the "Google Calendar API"');
    console.error('4. Go to "OAuth consent screen" -> add your email as test user');
    console.error('5. Go to "Credentials" -> Create OAuth 2.0 Client ID -> Desktop app');
    console.error(`6. Add "${REDIRECT_URI}" as an authorized redirect URI`);
    console.error('7. Download the JSON file');
    console.error(`8. Save it as: ${CREDENTIALS_PATH}\n`);
    console.error('Then run this script again.');
    process.exit(1);
  }

  const { clientId, clientSecret } = loadCredentials();
  console.log('Found credentials.json\n');

  // PKCE: generate code verifier and challenge
  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(crypto.createHash('sha256').update(codeVerifier).digest());
  const state = base64url(crypto.randomBytes(16));

  // Build auth URL
  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', SCOPE);
  authUrl.searchParams.set('access_type', 'offline');
  authUrl.searchParams.set('prompt', 'consent');
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('state', state);

  console.log('Open this URL in your browser to authorize:\n');
  console.log(authUrl.toString());
  console.log('\nWaiting for callback...\n');

  // Start local server to catch the redirect
  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url || '/', `http://localhost:${PORT}`);
      if (url.pathname !== '/oauth2callback') {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const error = url.searchParams.get('error');
      if (error) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<h1>Authorization failed</h1><p>${error}</p>`);
        console.error(`Authorization failed: ${error}`);
        server.close();
        process.exit(1);
      }

      const returnedState = url.searchParams.get('state');
      if (returnedState !== state) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<h1>State mismatch</h1>');
        console.error('State mismatch — possible CSRF');
        server.close();
        process.exit(1);
      }

      const code = url.searchParams.get('code');
      if (!code) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<h1>No code received</h1>');
        server.close();
        process.exit(1);
      }

      try {
        console.log('Received authorization code, exchanging for tokens...');
        const tokenData = await exchangeCode(code, clientId, clientSecret, codeVerifier);

        // Save in multi-account format expected by @cocal/google-calendar-mcp
        const tokens = {
          normal: {
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token,
            scope: tokenData.scope,
            token_type: tokenData.token_type,
            expiry_date: Date.now() + ((tokenData.expires_in as number) || 3600) * 1000,
          },
        };

        fs.writeFileSync(TOKENS_PATH, JSON.stringify(tokens, null, 2), { mode: 0o600 });

        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<h1>Authorization successful!</h1><p>You can close this tab.</p>');

        console.log(`\nTokens saved to ${TOKENS_PATH}`);
        console.log('\nNext steps:');
        console.log('  1. Rebuild the container: ./container/build.sh');
        console.log('  2. Restart NanoClaw');
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/html' });
        res.end(`<h1>Token exchange failed</h1><p>${err}</p>`);
        console.error(`Token exchange failed: ${err}`);
      }

      server.close();
      resolve();
    });

    server.listen(PORT, () => {
      console.log(`Listening on http://localhost:${PORT} for OAuth callback...`);
    });

    server.on('error', (err) => {
      console.error(`Failed to start server on port ${PORT}: ${err.message}`);
      console.error('Make sure port 3500 is not in use.');
      process.exit(1);
    });
  });
}

main();
