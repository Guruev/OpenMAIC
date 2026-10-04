import 'server-only';

import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  verify as verifySignature,
} from 'node:crypto';
import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const ISSUER = 'https://auth.openai.com';
const AUTHORIZE_ENDPOINT = ISSUER + '/api/accounts/authorize';
const TOKEN_ENDPOINT = ISSUER + '/api/accounts/oauth/token';
const JWKS_ENDPOINT = ISSUER + '/.well-known/jwks.json';
const REVOCATION_ENDPOINT = ISSUER + '/api/accounts/oauth/revoke';
const RESOURCE = 'https://api.openai.com/v1';
const RESPONSES_ENDPOINT = RESOURCE + '/responses';
const MODELS_ENDPOINT = RESOURCE + '/models';
const REQUIRED_SCOPE = 'chatgpt.tokens.use.direct';
const SCOPES = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct';
const DYNAMIC_CLIENT_ID = 'dynamic_agent_client';
const DATA_DIR = join(process.cwd(), 'data', 'chatgpt-plan');
const REGISTRATION_FILE = join(DATA_DIR, 'registration.json');
const SESSION_FILE = join(DATA_DIR, 'session.json');
const PENDING_FILE = join(DATA_DIR, 'pending.json');
const MAX_PENDING_AGE_MS = 10 * 60 * 1000;

interface Registration {
  version: 1;
  hostId: string;
  clientId?: string;
  subject?: string;
  email?: string;
}

interface Session {
  version: 1;
  clientId: string;
  subject: string;
  email?: string;
  idToken: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  scopes: string[];
  savedAt: string;
}

interface Pending {
  version: 1;
  state: string;
  nonce: string;
  verifier: string;
  redirectUri: string;
  requestedClientId: string;
  createdAt: number;
}

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
}

interface VerifiedIdentity {
  subject: string;
  email?: string;
}

export interface ChatGPTPlanModel {
  id: string;
  name: string;
}

export interface ChatGPTPlanStatus {
  available: boolean;
  connected: boolean;
  email?: string;
  reason?: string;
  models: ChatGPTPlanModel[];
}

let refreshInFlight: Promise<Session> | null = null;

function randomUrlSafe(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function parseScopes(value: unknown): string[] {
  return typeof value === 'string'
    ? value.split(/\s+/).map((scope) => scope.trim()).filter(Boolean)
    : [];
}

async function ensureDataDir(): Promise<void> {
  await mkdir(DATA_DIR, { recursive: true, mode: 0o700 });
  await chmod(DATA_DIR, 0o700).catch(() => undefined);
}

async function readJson<T>(path: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as T;
  } catch {
    return null;
  }
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await ensureDataDir();
  const temporary = path + '.' + process.pid + '.' + randomUrlSafe(8) + '.tmp';
  await writeFile(temporary, JSON.stringify(value) + '\n', { encoding: 'utf8', mode: 0o600 });
  await chmod(temporary, 0o600).catch(() => undefined);
  await rename(temporary, path);
}

async function removeFile(path: string): Promise<void> {
  await unlink(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== 'ENOENT') throw error;
  });
}

function localDeploymentReason(): string | undefined {
  if (process.env.OPENMAIC_ENABLE_CHATGPT_PLAN === 'false') {
    return 'ChatGPT plan sign-in is disabled by OPENMAIC_ENABLE_CHATGPT_PLAN=false.';
  }
  const published = process.env.OPENMAIC_PUBLISH_ADDRESS?.trim();
  if (published && !['127.0.0.1', 'localhost', '::1'].includes(published)) {
    return 'ChatGPT plan sign-in is restricted to a loopback-only OpenMAIC deployment.';
  }
  return undefined;
}

function requireAvailable(): void {
  const reason = localDeploymentReason();
  if (reason) throw new Error(reason);
}

async function registration(): Promise<Registration> {
  const existing = await readJson<Registration>(REGISTRATION_FILE);
  if (existing?.version === 1 && typeof existing.hostId === 'string') return existing;
  const created: Registration = { version: 1, hostId: 'urn:uuid:' + randomUUID() };
  await writeJson(REGISTRATION_FILE, created);
  return created;
}

function callbackUri(port: number): string {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Invalid loopback callback port.');
  }
  return 'http://127.0.0.1:' + port + '/auth/callback';
}

export async function beginChatGPTPlanSignIn(port: number): Promise<{ authorizationUrl: string }> {
  requireAvailable();
  const reg = await registration();
  const verifier = randomUrlSafe(48);
  const state = randomUrlSafe();
  const nonce = randomUrlSafe();
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const redirectUri = callbackUri(port);
  const requestedClientId = reg.clientId || DYNAMIC_CLIENT_ID;
  const pending: Pending = {
    version: 1,
    state,
    nonce,
    verifier,
    redirectUri,
    requestedClientId,
    createdAt: Date.now(),
  };
  await writeJson(PENDING_FILE, pending);

  const session = await readJson<Session>(SESSION_FILE);
  const url = new URL(AUTHORIZE_ENDPOINT);
  url.searchParams.set('client_id', requestedClientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', SCOPES);
  url.searchParams.set('resource', RESOURCE);
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('ext_agent_host_id', reg.hostId);
  if (requestedClientId === DYNAMIC_CLIENT_ID) {
    url.searchParams.set('agent_name_hint', 'OpenMAIC');
  } else {
    if (session?.idToken) url.searchParams.set('id_token_hint', session.idToken);
    if (reg.email) url.searchParams.set('login_hint', reg.email);
  }
  return { authorizationUrl: url.toString() };
}

function decodeJwtSegment(segment: string): Record<string, unknown> {
  const parsed = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Invalid OpenAI ID token.');
  }
  return parsed as Record<string, unknown>;
}

async function verifyIdToken(
  idToken: string,
  clientId: string,
  expectedNonce?: string,
): Promise<VerifiedIdentity> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Invalid OpenAI ID token.');
  const header = decodeJwtSegment(parts[0]);
  const payload = decodeJwtSegment(parts[1]);
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
    throw new Error('Unsupported OpenAI ID token signature.');
  }

  const jwksResponse = await fetch(JWKS_ENDPOINT, { redirect: 'error' });
  if (!jwksResponse.ok) throw new Error('Could not load OpenAI signing keys.');
  const jwks = (await jwksResponse.json()) as { keys?: Array<Record<string, unknown>> };
  const jwk = jwks.keys?.find((key) => key.kid === header.kid);
  if (!jwk) throw new Error('OpenAI signing key was not found.');
  const publicKey = createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' });
  const valid = verifySignature(
    'RSA-SHA256',
    Buffer.from(parts[0] + '.' + parts[1]),
    publicKey,
    Buffer.from(parts[2], 'base64url'),
  );
  if (!valid) throw new Error('OpenAI ID token signature is invalid.');

  const now = Math.floor(Date.now() / 1000);
  const audience = payload.aud;
  const audienceMatches =
    audience === clientId || (Array.isArray(audience) && audience.includes(clientId));
  if (
    payload.iss !== ISSUER ||
    !audienceMatches ||
    typeof payload.exp !== 'number' ||
    payload.exp < now - 5 ||
    typeof payload.iat !== 'number' ||
    typeof payload.sub !== 'string' ||
    !payload.sub
  ) {
    throw new Error('OpenAI ID token claims are invalid.');
  }
  if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
    throw new Error('OpenAI ID token nonce is invalid.');
  }
  return {
    subject: payload.sub,
    ...(typeof payload.email === 'string' ? { email: payload.email } : {}),
  };
}

async function requestTokens(body: URLSearchParams): Promise<TokenResponse> {
  const response = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body,
    redirect: 'error',
  });
  const payload = (await response.json().catch(() => ({}))) as TokenResponse;
  if (!response.ok) {
    const code = payload.error || 'oauth_error';
    throw new Error('OpenAI OAuth token exchange failed: ' + code);
  }
  return payload;
}

function requirePlanScope(scopes: string[]): void {
  if (!scopes.includes(REQUIRED_SCOPE)) {
    throw new Error('ChatGPT plan use was not authorized for OpenMAIC.');
  }
}

export async function completeChatGPTPlanSignIn(callbackUrl: URL): Promise<{ email?: string }> {
  requireAvailable();
  const pending = await readJson<Pending>(PENDING_FILE);
  if (!pending || Date.now() - pending.createdAt > MAX_PENDING_AGE_MS) {
    await removeFile(PENDING_FILE);
    throw new Error('The ChatGPT sign-in attempt expired.');
  }
  const returnedState = callbackUrl.searchParams.get('state') || '';
  if (!safeEqual(returnedState, pending.state)) {
    await removeFile(PENDING_FILE);
    throw new Error('The ChatGPT sign-in state did not match.');
  }
  if (callbackUrl.searchParams.get('error')) {
    await removeFile(PENDING_FILE);
    throw new Error('ChatGPT sign-in was not approved.');
  }
  const code = callbackUrl.searchParams.get('code');
  if (!code) {
    await removeFile(PENDING_FILE);
    throw new Error('ChatGPT did not return an authorization code.');
  }

  const reg = await registration();
  const returnedClientId = callbackUrl.searchParams.get('client_id') || undefined;
  let clientId: string;
  if (pending.requestedClientId === DYNAMIC_CLIENT_ID) {
    if (!returnedClientId || returnedClientId === DYNAMIC_CLIENT_ID) {
      throw new Error('ChatGPT registration did not return an issued client ID.');
    }
    clientId = returnedClientId;
  } else {
    if (returnedClientId && returnedClientId !== pending.requestedClientId) {
      throw new Error('ChatGPT returned a different client registration.');
    }
    clientId = pending.requestedClientId;
  }

  const tokens = await requestTokens(
    new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      redirect_uri: pending.redirectUri,
      code_verifier: pending.verifier,
      resource: RESOURCE,
    }),
  );
  if (
    !tokens.access_token ||
    !tokens.refresh_token ||
    !tokens.id_token ||
    typeof tokens.expires_in !== 'number'
  ) {
    throw new Error('OpenAI returned an incomplete token response.');
  }
  const scopes = parseScopes(tokens.scope);
  requirePlanScope(scopes);
  const identity = await verifyIdToken(tokens.id_token, clientId, pending.nonce);
  if (reg.subject && reg.clientId === clientId && reg.subject !== identity.subject) {
    throw new Error('The ChatGPT account did not match the saved registration.');
  }

  const nextRegistration: Registration = {
    version: 1,
    hostId: reg.hostId,
    clientId,
    subject: identity.subject,
    ...(identity.email ? { email: identity.email } : {}),
  };
  const nextSession: Session = {
    version: 1,
    clientId,
    subject: identity.subject,
    ...(identity.email ? { email: identity.email } : {}),
    idToken: tokens.id_token,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt: Date.now() + tokens.expires_in * 1000,
    scopes,
    savedAt: new Date().toISOString(),
  };
  await writeJson(REGISTRATION_FILE, nextRegistration);
  await writeJson(SESSION_FILE, nextSession);
  await removeFile(PENDING_FILE);
  return identity.email ? { email: identity.email } : {};
}

async function refreshSession(force = false): Promise<Session> {
  requireAvailable();
  const current = await readJson<Session>(SESSION_FILE);
  if (!current) throw new Error('Sign in with ChatGPT first.');
  requirePlanScope(current.scopes);
  if (!force && current.expiresAt > Date.now() + 60_000) return current;
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    const latest = (await readJson<Session>(SESSION_FILE)) || current;
    if (!force && latest.expiresAt > Date.now() + 60_000) return latest;
    const tokens = await requestTokens(
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: latest.clientId,
        refresh_token: latest.refreshToken,
        resource: RESOURCE,
      }),
    );
    if (!tokens.access_token || !tokens.refresh_token || typeof tokens.expires_in !== 'number') {
      throw new Error('OpenAI returned an incomplete refresh response.');
    }
    const scopes = tokens.scope ? parseScopes(tokens.scope) : latest.scopes;
    requirePlanScope(scopes);
    let identity: VerifiedIdentity = { subject: latest.subject, ...(latest.email ? { email: latest.email } : {}) };
    if (tokens.id_token) {
      identity = await verifyIdToken(tokens.id_token, latest.clientId);
      if (identity.subject !== latest.subject) {
        throw new Error('The refreshed ChatGPT identity changed unexpectedly.');
      }
    }
    const updated: Session = {
      version: 1,
      clientId: latest.clientId,
      subject: latest.subject,
      ...(identity.email || latest.email ? { email: identity.email || latest.email } : {}),
      idToken: tokens.id_token || latest.idToken,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Date.now() + tokens.expires_in * 1000,
      scopes,
      savedAt: new Date().toISOString(),
    };
    await writeJson(SESSION_FILE, updated);
    return updated;
  })();

  try {
    return await refreshInFlight;
  } finally {
    refreshInFlight = null;
  }
}

function normalizeResponsesBody(body: BodyInit | null | undefined): string {
  if (typeof body !== 'string') throw new Error('ChatGPT plan requests must use a JSON body.');
  const parsed = JSON.parse(body) as Record<string, unknown>;
  const unsupported = [
    'background',
    'conversation',
    'max_output_tokens',
    'max_tool_calls',
    'metadata',
    'moderation',
    'multi_agent',
    'prompt',
    'prompt_cache_retention',
    'safety_identifier',
    'temperature',
    'top_logprobs',
    'top_p',
    'truncation',
    'user',
    'previous_response_id',
  ];
  for (const field of unsupported) delete parsed[field];
  parsed.store = false;
  parsed.stream = true;
  if (Array.isArray(parsed.input)) {
    parsed.input = parsed.input.map((item) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) return item;
      const record = item as Record<string, unknown>;
      return record.role === 'system' ? { ...record, role: 'developer' } : record;
    });
  }
  return JSON.stringify(parsed);
}

async function authorizedFetch(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  forceRefresh: boolean,
): Promise<Response> {
  const url =
    typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
  if (url !== RESPONSES_ENDPOINT) {
    throw new Error('ChatGPT plan access is restricted to POST /v1/responses.');
  }
  const session = await refreshSession(forceRefresh);
  const headers = new Headers(init?.headers);
  headers.set('authorization', 'Bearer ' + session.accessToken);
  headers.set('content-type', 'application/json');
  return fetch(RESPONSES_ENDPOINT, {
    ...init,
    method: 'POST',
    body: normalizeResponsesBody(init?.body),
    headers,
    redirect: 'error',
  });
}

export async function chatGPTPlanFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  let response = await authorizedFetch(input, init, false);
  if (response.status === 401) {
    await response.body?.cancel().catch(() => undefined);
    response = await authorizedFetch(input, init, true);
  }
  return response;
}

export async function listChatGPTPlanModels(): Promise<ChatGPTPlanModel[]> {
  const session = await refreshSession(false);
  const response = await fetch(MODELS_ENDPOINT, {
    headers: { authorization: 'Bearer ' + session.accessToken },
    redirect: 'error',
  });
  if (!response.ok) throw new Error('Could not load models from the ChatGPT plan.');
  const payload = (await response.json()) as { models?: unknown[] };
  if (!Array.isArray(payload.models)) throw new Error('OpenAI returned an invalid model list.');
  return payload.models
    .filter((item): item is Record<string, unknown> => !!item && typeof item === 'object' && !Array.isArray(item))
    .filter((item) => item.visibility === 'list' && typeof item.slug === 'string')
    .map((item) => ({
      id: item.slug as string,
      name: typeof item.display_name === 'string' ? item.display_name : (item.slug as string),
    }));
}

export async function getChatGPTPlanStatus(): Promise<ChatGPTPlanStatus> {
  const reason = localDeploymentReason();
  if (reason) return { available: false, connected: false, reason, models: [] };
  const session = await readJson<Session>(SESSION_FILE);
  if (!session) return { available: true, connected: false, models: [] };
  try {
    const models = await listChatGPTPlanModels();
    return {
      available: true,
      connected: true,
      ...(session.email ? { email: session.email } : {}),
      models,
    };
  } catch {
    return {
      available: true,
      connected: true,
      ...(session.email ? { email: session.email } : {}),
      models: [],
    };
  }
}

export async function disconnectChatGPTPlan(): Promise<void> {
  const session = await readJson<Session>(SESSION_FILE);
  if (session?.refreshToken) {
    await fetch(REVOCATION_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: session.refreshToken,
        token_type_hint: 'refresh_token',
        client_id: session.clientId,
      }),
      redirect: 'error',
    }).catch(() => undefined);
  }
  await removeFile(SESSION_FILE);
  await removeFile(PENDING_FILE);
}
