import { isIP } from 'node:net';

// Optional bot check. With TURNSTILE_SITE_KEY and TURNSTILE_SECRET set, every examination needs a fresh
// token that Cloudflare's siteverify accepts for this action on one of TURNSTILE_HOSTNAMES.
export const ACTION = 'examine';
const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export interface Turnstile { siteKey: string; secret: string; hostnames: Set<string> }

export function turnstileFromEnv(env: NodeJS.ProcessEnv = process.env): Turnstile | null {
  const { TURNSTILE_SITE_KEY: siteKey, TURNSTILE_SECRET: secret } = env;
  if (!siteKey || !secret) return null;
  if (!/^[\w-]+$/.test(siteKey)) throw new Error('TURNSTILE_SITE_KEY is not a Turnstile site key.');
  const hostnames = new Set((env.TURNSTILE_HOSTNAMES ?? '').split(',').map((h) => h.trim()).filter(Boolean));
  if (!hostnames.size) throw new Error('TURNSTILE_HOSTNAMES must list the hostnames that serve this page.');
  return { siteKey, secret, hostnames };
}

/** Fails closed: a missing token, a siteverify error or any mismatch is a refusal. */
export async function verify(t: Turnstile, token: unknown, ip: string, fetchImpl: typeof fetch = fetch): Promise<boolean> {
  if (typeof token !== 'string' || !token || token.length > 2048 || !t.hostnames.size) return false;
  const body = new URLSearchParams({ secret: t.secret, response: token });
  if (isIP(ip)) body.set('remoteip', ip);
  try {
    const r = await fetchImpl(SITEVERIFY, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(10_000),
    });
    if (!r.ok) return false;
    const result = (await r.json()) as { success?: boolean; action?: string; hostname?: string };
    return result.success === true && result.action === ACTION && t.hostnames.has(result.hostname ?? '');
  } catch {
    return false;
  }
}
