import { z } from 'zod';
import { InvalidInputError, PolicyDeniedError } from './errors.js';
import { environmentSchema, projectSlugSchema, type SecretRef, type SecretScope } from './scope.js';

/**
 * Policy evaluation.
 *
 * Two design commitments, both from the threat model:
 *
 *  1. **Enforced in code, never in a prompt.** An agent that has been talked
 *     into asking for a production rotation still gets a `PolicyDeniedError`,
 *     because the decision happens here and not in a system message.
 *  2. **Deny by default.** An action absent from a project's allow list is
 *     denied. An unknown project is denied. A malformed policy file is a hard
 *     failure, not a fallback to permissive defaults.
 *
 * `humanApproval` is separate from `allow`: an action can be permitted *and*
 * require a gate outside the model. The engine reports that requirement; it is
 * the caller's job to obtain the approval through a channel the agent does not
 * control.
 */

export const ACTIONS = [
  'list',
  'describe',
  'request-create',
  'request-rotate',
  'create',
  'rotate',
  'delete',
  'run',
] as const;

export type Action = (typeof ACTIONS)[number];

export const actionSchema = z.enum(ACTIONS);

const environmentPolicySchema = z
  .object({
    allow: z.array(actionSchema).default([]),
    humanApproval: z.array(actionSchema).default([]),
  })
  .strict();

const projectPolicySchema = z
  .object({
    /**
     * Partial on purpose: a policy file names only the environments it wants to
     * override, and every other environment falls back to the built-in rules in
     * `DEFAULT_ENVIRONMENT_RULES`. `z.record` with an enum key is exhaustive in
     * Zod 4 and would force every file to spell out all three environments,
     * which `evaluate`'s fallback shows was never the intent. `partialRecord`
     * still rejects an unknown environment key, so nothing is loosened.
     */
    environments: z.partialRecord(environmentSchema, environmentPolicySchema),
  })
  .strict();

export const policyDocumentSchema = z
  .object({
    version: z.literal(1),
    projects: z.record(projectSlugSchema, projectPolicySchema).default({}),
    commands: z
      .object({
        /**
         * Executables that must never receive injected secrets. A denylist is
         * porous against a determined agent — `docs/threat-model.md` says so
         * plainly — but it stops the common accident of piping the environment
         * into a transcript.
         */
        denyExecutables: z.array(z.string().min(1)).default([]),
        /** When non-empty, only these executables may be run. */
        allowExecutables: z.array(z.string().min(1)).default([]),
      })
      .strict()
      .default({ denyExecutables: [], allowExecutables: [] }),
  })
  .strict();

export type PolicyDocument = z.infer<typeof policyDocumentSchema>;

export interface PolicyContext {
  readonly action: Action;
  readonly target: SecretRef | SecretScope;
  /** Executable name for `run`. Compared against the deny/allow lists. */
  readonly executable?: string;
  /** Set when a human approval has already been obtained out of band. */
  readonly approvalGranted?: boolean;
}

export interface PolicyDecision {
  readonly allowed: boolean;
  readonly requiresHumanApproval: boolean;
  /** Stable, non-secret explanation suitable for a log or a tool result. */
  readonly reason: string;
}

/**
 * The default policy when no `agent-secrets.policy.yaml` is present.
 *
 * Deliberately restrictive: development is fully usable, preview is read-only
 * plus execution, and production allows nothing at all. Per the PRD's own
 * recommendation (§31), production mutation stays disabled until after the
 * first public release; a user who wants it must write it down explicitly in a
 * policy file, which is exactly the kind of decision that should leave a trace.
 */
export function defaultPolicy(): PolicyDocument {
  return policyDocumentSchema.parse({
    version: 1,
    projects: {},
    commands: {
      denyExecutables: ['env', 'printenv', 'sh', 'bash', 'zsh', 'dash', 'fish', 'ksh'],
      allowExecutables: [],
    },
  });
}

const DEFAULT_ENVIRONMENT_RULES: Record<string, { allow: Action[]; humanApproval: Action[] }> = {
  development: {
    allow: [
      'list',
      'describe',
      'request-create',
      'request-rotate',
      'create',
      'rotate',
      'delete',
      'run',
    ],
    humanApproval: [],
  },
  preview: {
    allow: ['list', 'describe', 'request-create', 'request-rotate', 'run'],
    humanApproval: ['request-create', 'request-rotate'],
  },
  production: {
    allow: ['list', 'describe'],
    humanApproval: [],
  },
};

export function parsePolicy(raw: unknown): PolicyDocument {
  const parsed = policyDocumentSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    // Fail closed: a policy file we cannot understand is never treated as
    // "no restrictions".
    throw new InvalidInputError(
      `Policy file is invalid at ${first?.path.join('.') || 'root'}: ${first?.message ?? 'unknown issue'}`,
      {
        field: 'policy',
        hint: 'Fix the policy file or remove it to fall back to the built-in defaults.',
      },
    );
  }
  return parsed.data;
}

export class PolicyEngine {
  readonly #document: PolicyDocument;

  constructor(document: PolicyDocument = defaultPolicy()) {
    this.#document = document;
  }

  evaluate(context: PolicyContext): PolicyDecision {
    const { action, target } = context;
    const projectPolicy = this.#document.projects[target.project];
    const rules =
      projectPolicy?.environments[target.environment] ??
      DEFAULT_ENVIRONMENT_RULES[target.environment];

    if (!rules) {
      return {
        allowed: false,
        requiresHumanApproval: false,
        reason: `No policy covers ${target.project}/${target.environment}; denied by default.`,
      };
    }

    if (!rules.allow.includes(action)) {
      return {
        allowed: false,
        requiresHumanApproval: false,
        reason: `Action "${action}" is not allowed in ${target.project}/${target.environment}.`,
      };
    }

    if (action === 'run') {
      // Fail closed on an absent executable. Consulting the deny list only
      // when the caller remembered to supply one would make the entire list
      // opt-in from the call site — a caller that forgets gets a permissive
      // answer, which is precisely backwards for a security control.
      if (context.executable === undefined) {
        return {
          allowed: false,
          requiresHumanApproval: false,
          reason: 'A "run" decision requires the executable; refusing without one.',
        };
      }
      const executableDecision = this.#checkExecutable(context.executable);
      if (executableDecision) {
        return executableDecision;
      }
    }

    const needsApproval = rules.humanApproval.includes(action);
    if (needsApproval && !context.approvalGranted) {
      return {
        allowed: false,
        requiresHumanApproval: true,
        reason: `Action "${action}" in ${target.project}/${target.environment} requires human approval.`,
      };
    }

    return {
      allowed: true,
      requiresHumanApproval: needsApproval,
      reason: `Action "${action}" is allowed in ${target.project}/${target.environment}.`,
    };
  }

  /** Evaluate and throw `PolicyDeniedError` when the answer is no. */
  assert(context: PolicyContext): PolicyDecision {
    const decision = this.evaluate(context);
    if (!decision.allowed) {
      throw new PolicyDeniedError(decision.reason, {
        reference: `${context.target.project}/${context.target.environment}`,
        hint: decision.requiresHumanApproval
          ? 'Obtain approval through a channel the agent does not control, then retry.'
          : 'Adjust agent-secrets.policy.yaml if this action should be permitted.',
      });
    }
    return decision;
  }

  #checkExecutable(executable: string): PolicyDecision | null {
    const basename = normalizeExecutable(executable);
    const { denyExecutables, allowExecutables } = this.#document.commands;

    if (denyExecutables.map(normalizeExecutable).includes(basename)) {
      return {
        allowed: false,
        requiresHumanApproval: false,
        reason: `Executable "${basename}" is on the deny list.`,
      };
    }
    // An allow list is a boundary, so it is matched strictly: an entry
    // containing a separator must equal the full path, and a bare-name entry
    // matches only a bare name. Comparing basenames both ways would let
    // `/tmp/evil/npm` satisfy an allow list of `["npm"]` — defeating the
    // boundary by naming a file.
    if (allowExecutables.length > 0 && !isAllowed(executable, allowExecutables)) {
      return {
        allowed: false,
        requiresHumanApproval: false,
        reason: `Executable "${basename}" is not on the allow list.`,
      };
    }
    return null;
  }
}

/**
 * Reduce an executable to the token the deny and allow lists are written in.
 *
 * The naive `split('/').pop()` misses several spellings of the same program:
 * `/bin/sh`, `./sh`, `sh ` with a trailing space, `SH` on a case-insensitive
 * filesystem. Each of those would otherwise walk straight past a list entry of
 * `sh`. A backslash is treated as a separator too, so a Windows-style path does
 * not become a bypass on a case-insensitive volume.
 *
 * This does not make a denylist sufficient — `docs/threat-model.md` is explicit
 * that a determined agent can copy a shell to another name — but it removes the
 * spellings that would defeat it by accident or with no effort at all.
 */
/**
 * Strict allow-list matching.
 *
 * An entry with a path separator is a path and must match exactly (after
 * trimming). An entry without one names a program and matches only an
 * invocation that also has no path, so a caller cannot smuggle a different
 * binary in by giving a directory.
 */
function isAllowed(executable: string, allowExecutables: readonly string[]): boolean {
  const invoked = executable.trim();
  const invokedHasPath = /[/\\]/.test(invoked);

  return allowExecutables.some((entry) => {
    const candidate = entry.trim();
    const entryHasPath = /[/\\]/.test(candidate);

    if (entryHasPath) {
      return candidate === invoked;
    }
    return !invokedHasPath && normalizeExecutable(candidate) === normalizeExecutable(invoked);
  });
}

function normalizeExecutable(executable: string): string {
  const trimmed = executable.trim();
  const basename = trimmed.split(/[/\\]/).pop() ?? trimmed;
  return basename.toLowerCase();
}
