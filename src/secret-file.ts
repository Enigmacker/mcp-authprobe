import { closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync, openSync, readSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { basename, dirname, join } from "node:path";

/**
 * One reader and one writer for every file that holds a secret: the
 * ownership secret, a static key, an access token, a client secret, a test
 * grant. The file is opened once and judged through its descriptor (no
 * check-then-use gap): it must be a regular file of bounded size, and a file
 * other users can read gets a warning. Content never reaches an error message.
 */

export class SecretFileError extends Error {}

export interface SecretFileOptions {
  /** What the file is, for messages: "key file", "credentials file". */
  label: string;
  /** Largest size accepted, in bytes. */
  maxBytes: number;
  /**
   * Follow a symbolic link (default false). Files the operator mounts, such
   * as the ownership secret or a grant in a container secret volume, are
   * commonly links; the link is then followed and its target judged.
   */
  followLinks?: boolean;
}

export function readSecretFile(path: string, o: SecretFileOptions): { text: string; warnings: string[] } {
  const warnings: string[] = [];
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (o.followLinks ? 0 : (constants.O_NOFOLLOW ?? 0)));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "error";
    throw new SecretFileError(`Cannot read the ${o.label} ${path}: ${code === "ELOOP" ? "it is a symbolic link" : code}.`);
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new SecretFileError(`${path} is not a regular file.`);
    if (st.size > o.maxBytes) throw new SecretFileError(`${path} is larger than ${o.maxBytes >= 1024 * 1024 ? `${o.maxBytes / 1024 / 1024} MiB` : `${o.maxBytes / 1024} KiB`}; this is not a ${o.label}.`);
    if (process.platform !== "win32" && (st.mode & 0o077) !== 0) {
      warnings.push(`${path} is readable by other users (mode ${(st.mode & 0o777).toString(8)}); chmod 600 it.`);
    }
    const buf = Buffer.alloc(st.size);
    let read = 0;
    while (read < st.size) {
      const n = readSync(fd, buf, read, st.size - read, read);
      if (n === 0) break;
      read += n;
    }
    return { text: buf.subarray(0, read).toString("utf8"), warnings };
  } finally {
    closeSync(fd);
  }
}

/** One secret on one line (a key, a token, a client secret). */
export function readSecretLine(path: string, o: SecretFileOptions & { minLength?: number }): { value: string; warnings: string[] } {
  const { text, warnings } = readSecretFile(path, o);
  const value = text.trim();
  if (!value) throw new SecretFileError(`${path} is empty.`);
  if (value.length < (o.minLength ?? 1)) throw new SecretFileError(`${path} holds fewer than ${o.minLength} characters; this is not a ${o.label}.`);
  if (/[\s\u0000-\u001f\u007f]/.test(value)) throw new SecretFileError(`${path} must contain one value on one line, without spaces.`);
  return { value, warnings };
}

/**
 * Write a secret file with mode 600, atomically: the content goes to a new
 * file next to the target, which then replaces it by a rename. An
 * interruption leaves the old file intact. The target is never written
 * through a symbolic link, and is only replaced when `overwrite` is set.
 */
export function writeSecretFile(path: string, content: string, overwrite: boolean): void {
  let existing: ReturnType<typeof lstatSync> | null = null;
  try {
    existing = lstatSync(path);
  } catch {
    existing = null;
  }
  if (existing?.isSymbolicLink()) throw Object.assign(new Error(`ELOOP: ${path} is a symbolic link; refusing to write through it.`), { code: "ELOOP" });
  if (existing && !existing.isFile()) throw Object.assign(new Error(`${path} is not a regular file.`), { code: "EINVAL" });
  if (existing && !overwrite) throw Object.assign(new Error(`EEXIST: ${path} already exists.`), { code: "EEXIST" });

  const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    if (process.platform !== "win32") fchmodSync(fd, 0o600);
    writeSync(fd, content);
    fsyncSync(fd);
  } catch (e) {
    closeSync(fd);
    try {
      unlinkSync(tmp);
    } catch {
      /* nothing to remove */
    }
    throw e;
  }
  closeSync(fd);
  try {
    renameSync(tmp, path);
  } catch (e) {
    try {
      unlinkSync(tmp);
    } catch {
      /* nothing to remove */
    }
    throw e;
  }
}
