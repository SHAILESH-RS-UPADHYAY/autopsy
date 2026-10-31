import { DurableObject } from 'cloudflare:workers';

// The examiner needs node:tls peer certificates and its own DNS resolver, which the Workers runtime
// does not offer. So the Node server runs unchanged in a container and this Worker only forwards to it.
const PORT = 3000;

interface Env { TURNSTILE_SITE_KEY?: string; TURNSTILE_SECRET?: string; TURNSTILE_HOSTNAMES?: string }

// One instance on purpose: the rate limiter and the ten-minute report cache live in its memory.
export class Examiner extends DurableObject<Env> {
  private starting?: Promise<void>;

  async fetch(request: Request) {
    this.starting ??= this.boot().finally(() => (this.starting = undefined));
    await this.starting;
    const url = new URL(request.url);
    url.protocol = 'http:';
    url.host = 'container';
    return this.ctx.container!.getTcpPort(PORT).fetch(new Request(url, request));
  }

  private async boot() {
    const container = this.ctx.container!;
    if (!container.running) {
      const { TURNSTILE_SITE_KEY = '', TURNSTILE_SECRET = '', TURNSTILE_HOSTNAMES = '' } = this.env;
      // Internet on: examining other websites is the whole job. The server's own guard refuses private addresses.
      container.start({ enableInternet: true, env: { PORT: String(PORT), TRUST_PROXY: '1', TURNSTILE_SITE_KEY, TURNSTILE_SECRET, TURNSTILE_HOSTNAMES } });
    }
    await container.setInactivityTimeout(10 * 60_000);
    const port = container.getTcpPort(PORT);
    for (let i = 0; i < 100; i++) {
      try {
        const r = await port.fetch('http://container/api/health', { signal: AbortSignal.timeout(1000) });
        await r.body?.cancel();
        if (r.ok) return;
      } catch { /* not listening yet */ }
      await scheduler.wait(200);
    }
    throw new Error('The examiner container did not start.');
  }
}

export default {
  fetch(request, _env, ctx) {
    // The examiner trusts x-forwarded-for, so it is set here from the address Cloudflare saw, never by the client.
    const headers = new Headers(request.headers);
    headers.set('x-forwarded-for', request.headers.get('cf-connecting-ip') ?? '');
    return ctx.exports.Examiner.getByName('examiner').fetch(new Request(request, { headers }));
  },
} satisfies ExportedHandler<Env>;
