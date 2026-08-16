import { timingSafeEqual } from 'node:crypto';
import { BitwardenBackend } from '@bx-labs/agent-secrets-backend-bitwarden';
import {
  buildAuditEvent,
  ExpiredOrConsumedError,
  environmentSchema,
  formatRef,
  InvalidInputError,
  isAgentSecretsError,
  makeRef,
  projectSlugSchema,
  SecretValue,
  secretNameSchema,
  validateSecretValue,
} from '@bx-labs/agent-secrets-core';
import { RedactionScope } from '@bx-labs/agent-secrets-redaction';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance, LogController } from 'fastify';
import { z } from 'zod';
import { SqliteAuditSink } from './audit-sink.js';
import type { ApiConfig } from './config.js';
import {
  contentSecurityPolicy,
  newNonces,
  renderForm,
  renderResult,
  SECURITY_HEADERS,
} from './form.js';
import { RequestStore } from './store.js';

/**
 * The HTTP surface.
 *
 * Four routes and no more. Everything about the shape of this file is driven by
 * one rule: the request body of `POST /v1/input/:token` contains a raw secret
 * value, so it must never be logged, never be echoed, never be retained, and
 * never be visible to anything that was not written with that in mind.
 *
 * The concrete consequences are worth stating, because they look like quirks
 * otherwise:
 *   - Fastify's request logging is disabled for the submit route, and the
 *     serializers below never touch `request.body`;
 *   - error responses are generic; a validation failure says "invalid
 *     submission", never which character was wrong;
 *   - the CSRF token check runs before the body is even looked at;
 *   - the token is claimed *before* the backend write is attempted, so a crash
 *     mid-write leaves a consumed request rather than a replayable one.
 */

export interface BuildServerOptions {
  readonly config: ApiConfig;
  readonly store?: RequestStore;
  /** Injected in tests so no real vault is touched. */
  readonly backendFactory?: () => {
    create: BitwardenBackend['create'];
    update: BitwardenBackend['update'];
    describe: BitwardenBackend['describe'];
    health: BitwardenBackend['health'];
  };
}

const createRequestBodySchema = z
  .object({
    action: z.enum(['create', 'rotate']),
    project: projectSlugSchema,
    environment: environmentSchema,
    name: secretNameSchema,
    telegramUserId: z.string().max(64).optional(),
  })
  .strict();

export async function buildServer(options: BuildServerOptions): Promise<FastifyInstance> {
  const { config } = options;
  const store = options.store ?? new RequestStore(config.databasePath);
  const audit = new SqliteAuditSink(store.database);

  const backend =
    options.backendFactory?.() ??
    new BitwardenBackend({
      accessToken: config.bitwarden.accessToken,
      projectId: config.bitwarden.projectId,
      ...(config.bitwarden.executablePath === undefined
        ? {}
        : { executable: config.bitwarden.executablePath }),
      ...(config.bitwarden.serverUrl === undefined
        ? {}
        : { serverUrl: config.bitwarden.serverUrl }),
    });

  const app = Fastify({
    trustProxy: config.trustProxy,
    // Cap the body well below the value limit's worst-case encoding, so an
    // oversized submission is rejected by the framework before it is buffered.
    bodyLimit: Math.max(config.maxValueBytes * 2, 8 * 1024),
    // Automatic per-request logging is off because the request URL of the form
    // route carries the one-time token, and Fastify's built-in request log
    // writes the URL. Configured through LogController, since the top-level
    // `disableRequestLogging` option is deprecated in Fastify 5.12.
    logController: new LogController({ disableRequestLogging: true }),
    logger: {
      level: config.nodeEnv === 'production' ? 'info' : 'debug',
      /**
       * Pino's own redaction, with `remove: true` so the keys disappear rather
       * than being replaced by a placeholder that still proves they existed.
       *
       * The list is the interesting part. `req.url` is here because the form
       * route embeds the one-time token in the path, and a URL in a log file is
       * a working link for as long as it has not been claimed. `req.body` and
       * `body` are here because the submit route's body *is* the secret.
       * `headers.cookie` carries the CSRF token. None of these has any
       * diagnostic value that the route pattern and status code do not already
       * provide.
       */
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'req.headers["x-forwarded-for"]',
          'req.url',
          'req.body',
          'res.headers["set-cookie"]',
          'body',
          'value',
          'token',
          'url',
          'headers.authorization',
          'headers.cookie',
        ],
        remove: true,
      },
    },
  });

  await app.register(cookie, { parseOptions: { httpOnly: true, sameSite: 'strict', path: '/' } });
  await app.register(formbody, { bodyLimit: Math.max(config.maxValueBytes * 2, 8 * 1024) });
  await app.register(rateLimit, {
    global: false,
    max: config.rateLimit.max,
    timeWindow: config.rateLimit.windowMs,
  });

  app.addHook('onSend', async (_request, reply, payload) => {
    for (const [header, value] of Object.entries(SECURITY_HEADERS)) {
      reply.header(header, value);
    }
    return payload;
  });

  /** POST /v1/requests — the Telegram adapter asks for a one-time link. */
  app.post(
    '/v1/requests',
    { config: { rateLimit: { max: config.rateLimit.max, timeWindow: config.rateLimit.windowMs } } },
    async (request, reply) => {
      if (!checkAdapterCredential(request, config.adapterToken)) {
        // 401 with no detail. Telling an unauthenticated caller that the
        // credential was "close" would be a probing oracle.
        return reply.code(401).send({ error: 'unauthorized' });
      }

      const parsed = createRequestBodySchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }

      // Round-trips through the canonical grammar so the stored request cannot
      // hold anything the rest of the system would refuse.
      const ref = makeRef({
        project: parsed.data.project,
        environment: parsed.data.environment,
        name: parsed.data.name,
      });

      const issued = store.create({
        action: parsed.data.action,
        project: ref.project,
        environment: ref.environment,
        secretName: ref.name,
        ttlMs: config.ttlSeconds * 1000,
        ...(parsed.data.telegramUserId === undefined
          ? {}
          : { telegramUserId: parsed.data.telegramUserId }),
      });

      await audit.record(
        buildAuditEvent({
          actorType: 'telegram',
          actorId: parsed.data.telegramUserId ?? 'adapter',
          operation: parsed.data.action === 'create' ? 'request-create' : 'request-rotate',
          reference: formatRef(ref),
          outcome: 'success',
        }),
      );

      // The URL is sensitive but is not the value. It is returned here and
      // never written to a log — see the request serializer above.
      return reply.code(201).send({
        id: issued.request.id,
        url: `${config.publicUrl.replace(/\/$/, '')}/input/${issued.token}`,
        expiresAt: issued.request.expiresAt,
      });
    },
  );

  /** GET /input/:token — render the form. Does not consume the token. */
  app.get<{ Params: { token: string } }>(
    '/input/:token',
    { config: { rateLimit: { max: config.rateLimit.max, timeWindow: config.rateLimit.windowMs } } },
    async (request, reply) => {
      const found = store.peek(request.params.token);
      if (!found) {
        return reply
          .code(404)
          .type('text/html; charset=utf-8')
          .send(
            renderResult({
              ok: false,
              title: 'This link is no longer valid',
              message: 'Links work once and expire after a couple of minutes. Ask for a new one.',
            }),
          );
      }

      const nonces = newNonces();
      // The CSRF token is bound to this rendering and returned in a cookie that
      // the submit handler compares against the form field: a cross-site POST
      // cannot read the cookie, so it cannot forge a matching pair.
      reply.setCookie('as_csrf', nonces.csrf, {
        httpOnly: true,
        sameSite: 'strict',
        secure: config.nodeEnv === 'production',
        path: '/',
        maxAge: config.ttlSeconds,
      });

      const secondsRemaining = (new Date(found.expiresAt).getTime() - Date.now()) / 1000;

      return reply
        .code(200)
        .type('text/html; charset=utf-8')
        .header('Content-Security-Policy', contentSecurityPolicy(nonces.script))
        .send(
          renderForm({
            request: found,
            token: request.params.token,
            nonces,
            maxValueBytes: config.maxValueBytes,
            secondsRemaining,
          }),
        );
    },
  );

  /** POST /v1/input/:token — receive the value and write it to the vault. */
  app.post<{ Params: { token: string }; Body: { value?: unknown; csrf?: unknown } }>(
    '/v1/input/:token',
    {
      config: {
        rateLimit: {
          max: config.rateLimit.maxAttemptsPerRequest,
          timeWindow: config.rateLimit.windowMs,
        },
      },
    },
    async (request, reply) => {
      const scope = new RedactionScope();
      let value: SecretValue | undefined;

      try {
        if (!checkCsrf(request)) {
          return reply
            .code(403)
            .type('text/html; charset=utf-8')
            .send(
              renderResult({
                ok: false,
                title: 'Rejected',
                message:
                  'This submission did not come from the form we served. Open the link again.',
              }),
            );
        }

        if (!checkOrigin(request, config.publicUrl)) {
          return reply
            .code(403)
            .type('text/html; charset=utf-8')
            .send(
              renderResult({
                ok: false,
                title: 'Rejected',
                message: 'This submission was refused.',
              }),
            );
        }

        const submitted = request.body?.value;
        if (typeof submitted !== 'string' || submitted.length === 0) {
          // Note what is absent: the submitted content, its length, and which
          // check failed.
          return reply
            .code(400)
            .type('text/html; charset=utf-8')
            .send(
              renderResult({
                ok: false,
                title: 'Invalid submission',
                message: 'No value was received.',
              }),
            );
        }

        // Claim first. If the process dies during the backend write, the
        // request is already burned — a lost write is recoverable by asking for
        // a new link; a replayable token is not.
        const claimed = store.claim(request.params.token);

        value = SecretValue.from(submitted);
        scope.track(value);
        validateSecretValue(value, { maxBytes: config.maxValueBytes });

        const ref = makeRef({
          project: claimed.project,
          environment: claimed.environment,
          name: claimed.secretName,
        });

        try {
          if (claimed.action === 'create') {
            await backend.create(ref, value);
          } else {
            await backend.update(ref, value);
          }
          store.settle(claimed.id, 'succeeded');
        } catch (error) {
          store.settle(claimed.id, 'failed');
          await audit.record(
            buildAuditEvent({
              actorType: 'human',
              actorId: claimed.telegramUserId ?? 'web',
              operation: claimed.action === 'create' ? 'create' : 'rotate',
              reference: formatRef(ref),
              outcome: 'failure',
              errorCode: isAgentSecretsError(error) ? error.code : 'INTERNAL',
            }),
          );
          throw error;
        }

        await audit.record(
          buildAuditEvent({
            actorType: 'human',
            actorId: claimed.telegramUserId ?? 'web',
            operation: claimed.action === 'create' ? 'create' : 'rotate',
            reference: formatRef(ref),
            outcome: 'success',
          }),
        );

        return reply
          .code(200)
          .type('text/html; charset=utf-8')
          .send(
            renderResult({
              ok: true,
              title: 'Saved',
              message: 'The value was written to your vault. It was not stored on this server.',
              reference: formatRef(ref),
            }),
          );
      } catch (error) {
        const status =
          error instanceof ExpiredOrConsumedError
            ? 410
            : error instanceof InvalidInputError
              ? 400
              : 500;
        const title =
          error instanceof ExpiredOrConsumedError
            ? 'This link is no longer valid'
            : error instanceof InvalidInputError
              ? 'The value was rejected'
              : 'Something went wrong';
        const message = isAgentSecretsError(error)
          ? error.message
          : 'The value could not be saved. Nothing was written.';

        return reply
          .code(status)
          .type('text/html; charset=utf-8')
          .send(renderResult({ ok: false, title, message }));
      } finally {
        // FR-WEB-012. The value's job is done the moment the backend accepted
        // it; holding it any longer only widens the window in which a crash
        // dump could contain it.
        value?.dispose();
        scope.dispose();
      }
    },
  );

  app.get<{ Params: { id: string } }>('/v1/requests/:id/status', async (request, reply) => {
    if (!checkAdapterCredential(request, config.adapterToken)) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
    const found = store.status(request.params.id);
    if (!found) {
      return reply.code(404).send({ error: 'not_found' });
    }
    // Metadata only, and deliberately not the token hash.
    return reply.send({
      id: found.id,
      action: found.action,
      project: found.project,
      environment: found.environment,
      name: found.secretName,
      status: found.status,
      createdAt: found.createdAt,
      expiresAt: found.expiresAt,
      consumedAt: found.consumedAt,
    });
  });

  app.get('/health/live', async () => ({ status: 'ok' }));

  app.get('/health/ready', async (_request, reply) => {
    const health = await backend.health();
    // Reports reachability without listing projects or echoing any identifier
    // that would map out the vault for an unauthenticated caller.
    return reply.code(health.reachable ? 200 : 503).send({
      status: health.reachable ? 'ready' : 'unavailable',
      backendLatencyMs: health.latencyMs,
    });
  });

  app.addHook('onClose', async () => {
    store.close();
  });

  return app;
}

/**
 * Compare the adapter credential in constant time.
 *
 * A `===` here would leak the credential one byte at a time to a patient
 * attacker measuring response latency. The length check before the comparison
 * is unavoidable (`timingSafeEqual` requires equal lengths) and leaks only the
 * length, which is fixed by configuration.
 */
interface CredentialCarrier {
  headers: { authorization?: string | undefined };
}

function checkAdapterCredential(request: CredentialCarrier, expected: string): boolean {
  const header = request.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) {
    return false;
  }
  const provided = Buffer.from(header.slice('Bearer '.length), 'utf8');
  const reference = Buffer.from(expected, 'utf8');
  return provided.length === reference.length && timingSafeEqual(provided, reference);
}

/**
 * Double-submit cookie check.
 *
 * The form carries a random token in a hidden field; the same token is set as a
 * `SameSite=Strict; HttpOnly` cookie when the page is rendered. A cross-site
 * page can make the browser POST here, but it can neither read the cookie nor
 * guess the field, so the pair cannot be made to match. Compared in constant
 * time out of habit rather than necessity — the token is single-use and
 * short-lived.
 */
interface CsrfCarrier {
  body?: unknown;
  cookies?: Record<string, string | undefined> | undefined;
}

function checkCsrf(request: CsrfCarrier): boolean {
  const submitted = (request.body as { csrf?: unknown } | undefined)?.csrf;
  const cookieValue = request.cookies?.['as_csrf'];
  if (typeof submitted !== 'string' || typeof cookieValue !== 'string') {
    return false;
  }
  const a = Buffer.from(submitted, 'utf8');
  const b = Buffer.from(cookieValue, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * FR-WEB-011. `Origin` is set by the browser on every cross-origin POST and
 * cannot be forged by page script, which makes it a reliable same-origin check
 * for a form that is only ever submitted from our own page.
 */
interface OriginCarrier {
  headers: { origin?: string | undefined; referer?: string | undefined };
}

function checkOrigin(request: OriginCarrier, publicUrl: string): boolean {
  const origin = request.headers.origin;
  if (origin === undefined) {
    // Some privacy tools strip Origin on same-origin requests. Falling back to
    // Referer keeps those users working; when both are absent we accept, since
    // the one-time token remains the primary control and a CSRF that cannot
    // read it can only replay a link the victim already holds.
    const referer = request.headers.referer;
    return referer === undefined || referer.startsWith(publicUrl);
  }
  return origin === publicUrl.replace(/\/$/, '');
}
