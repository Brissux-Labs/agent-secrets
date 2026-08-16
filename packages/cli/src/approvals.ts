import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { type ApprovalRecord, approvalRecordSchema, type LoadedManifest } from './manifest.js';

/**
 * Persisted manifest approvals.
 *
 * A manifest arrives with a repository, so the commands in it are untrusted
 * until a human has looked at one and said yes. This file is where that "yes"
 * lives.
 *
 * The record is keyed by (manifest path, content digest, command name). The
 * digest is what makes the approval meaningful: editing the manifest — adding a
 * secret to a command, changing what it executes — produces a different digest,
 * so the previous approval no longer matches and the human is asked again. An
 * approval is consent to a specific command, not standing consent to a file.
 *
 * It lives beside the CLI's own config rather than in the project directory, for
 * the obvious reason: an approvals file a repository could ship would approve
 * itself.
 */

export function approvalsPath(configHome: string): string {
  return join(configHome, 'manifest-approvals.json');
}

export async function loadApprovals(configHome: string): Promise<ApprovalRecord> {
  const path = approvalsPath(configHome);
  try {
    const parsed = approvalRecordSchema.safeParse(JSON.parse(await readFile(path, 'utf8')));
    // A malformed approvals file means nothing is approved. Failing closed here
    // costs one confirmation prompt; failing open would honour approvals we
    // cannot actually read.
    return parsed.success ? parsed.data : { version: 1, approvals: [] };
  } catch {
    return { version: 1, approvals: [] };
  }
}

export async function recordApproval(
  configHome: string,
  loaded: LoadedManifest,
  command: string,
  now: Date = new Date(),
): Promise<ApprovalRecord> {
  const existing = await loadApprovals(configHome);

  // Drop any earlier approval for this manifest path and command, whatever its
  // digest: keeping stale entries would grow the file forever and make it
  // harder to see what is actually trusted.
  const approvals = existing.approvals.filter(
    (approval) => !(approval.manifestPath === loaded.path && approval.command === command),
  );

  approvals.push({
    manifestPath: loaded.path,
    digest: loaded.digest,
    command,
    approvedAt: now.toISOString(),
  });

  const record: ApprovalRecord = { version: 1, approvals };
  const path = approvalsPath(configHome);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(record, null, 2)}\n`, {
    mode: 0o600,
    encoding: 'utf8',
  });
  await chmod(path, 0o600);
  return record;
}

export async function revokeApprovals(configHome: string, manifestPath?: string): Promise<number> {
  const existing = await loadApprovals(configHome);
  const kept = manifestPath
    ? existing.approvals.filter((approval) => approval.manifestPath !== manifestPath)
    : [];
  const removed = existing.approvals.length - kept.length;

  const path = approvalsPath(configHome);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify({ version: 1, approvals: kept }, null, 2)}\n`, {
    mode: 0o600,
    encoding: 'utf8',
  });
  return removed;
}
