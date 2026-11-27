import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const [directory, task, profile, nextStage, expectedRevision] = process.argv.slice(2);
const stages = ['planned', 'profile_created', 'browser_verified', 'email_pending', 'verification_pending', 'terms_pending', 'onboarding', 'ready', 'awaiting_user', 'blocked', 'failed'];
if (!directory || !/^[\w-]{1,64}$/.test(task || '') || !/^[\w-]{1,64}$/.test(profile || '') || !stages.includes(nextStage)) {
  throw new Error('Usage: node state.mjs <private-directory> <task-id> <profile-id> <stage> <expected-revision; 0 for new>');
}
const root = path.resolve(directory);
const repository = path.dirname(fileURLToPath(import.meta.url));
const relative = path.relative(repository, root);
if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) throw new Error('State must be outside repository');
await fs.mkdir(root, { recursive: true });
const target = path.join(root, task + '.state.json');
const lockPath = target + '.lock';
const lock = await fs.open(lockPath, 'wx');
const temporary = target + '.' + crypto.randomUUID() + '.tmp';
try {
  let current = null;
  try { current = JSON.parse(await fs.readFile(target, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (current && current.profile !== profile) throw new Error('Task is already bound to another profile');
  if (Number(expectedRevision) !== (current?.revision || 0)) throw new Error('Revision conflict; read state before retrying');
  const event = { stage: nextStage, at: new Date().toISOString() };
  const updated = { task, profile, revision: (current?.revision || 0) + 1, ...event, history: [...(current?.history || []), event] };
  await fs.writeFile(temporary, JSON.stringify(updated, null, 2), { flag: 'wx' });
  await fs.rename(temporary, target);
  console.log(JSON.stringify(updated));
} finally {
  await fs.rm(temporary, { force: true });
  await lock.close();
  await fs.unlink(lockPath);
}
