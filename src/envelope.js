// The local half of envelope encryption: AES-256-GCM with the data key the KMS just handed over.
// The deed reference is the additional authenticated data, so a ciphertext copied onto another
// row fails to open.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export function seal(plaintext, key, ref) {
  if (key.length !== 32) throw new Error('A data key is 32 bytes');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(ref, 'utf8'));
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), body };
}

export function open({ iv, tag, body }, key, ref) {
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(ref, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
}

// The data key lives a few milliseconds: overwrite it as soon as the deed is sealed or read.
export function wipe(key) {
  if (Buffer.isBuffer(key)) key.fill(0);
}
