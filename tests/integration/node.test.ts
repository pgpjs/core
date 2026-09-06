import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { generateKeyPair } from '../../packages/core/src/index.js';
import {
  encryptFile,
  decryptFile,
  signFile,
  verifyFile,
  createNodeEncryptStream,
  createNodeDecryptStream
} from '../../packages/node/src/index.js';

describe('@pgpjs/node Adapters', () => {
  it('encrypts and decrypts files on the filesystem', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'pgpjs-node-test-'));
    const inputFile = path.join(tmpDir, 'input.txt');
    const encryptedFile = path.join(tmpDir, 'encrypted.pgp');
    const outputFile = path.join(tmpDir, 'decrypted.txt');

    const originalData = 'Filesystem encryption & decryption test with @pgpjs/node';
    await fs.writeFile(inputFile, originalData, 'utf-8');

    const key = await generateKeyPair({ userIDs: ['Node User <node@example.com>'] });

    await encryptFile(inputFile, encryptedFile, {
      encryptionKeys: key.publicKey
    });

    const encStats = await fs.stat(encryptedFile);
    expect(encStats.size).toBeGreaterThan(0);

    const result = await decryptFile(encryptedFile, outputFile, {
      decryptionKeys: key.privateKey
    });

    expect(result.text).toBe(originalData);
    const readOutput = await fs.readFile(outputFile, 'utf-8');
    expect(readOutput).toBe(originalData);

    // Clean up
    await fs.rm(tmpDir, { recursive: true, force: true });
  }, 15000);

  it('signs and verifies files on the filesystem', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'pgpjs-node-sig-'));
    const docFile = path.join(tmpDir, 'doc.txt');
    const sigFile = path.join(tmpDir, 'doc.txt.asc');

    const content = 'Legally binding document to sign';
    await fs.writeFile(docFile, content, 'utf-8');

    const key = await generateKeyPair({ userIDs: ['Signer <signer@example.com>'] });

    await signFile(docFile, sigFile, {
      signingKeys: key.privateKey,
      detached: true
    });

    const verifyResult = await verifyFile(docFile, sigFile, {
      verificationKeys: key.publicKey
    });

    expect(verifyResult.signatures.length).toBe(1);
    expect(verifyResult.signatures[0].valid).toBe(true);

    // Clean up
    await fs.rm(tmpDir, { recursive: true, force: true });
  }, 15000);

  it('streams data through Node.js Transform streams', async () => {
    const key = await generateKeyPair({ userIDs: ['Node Streamer <streamer@example.com>'] });
    const inputContent = 'Piping data through Node.js Transform streams';

    const source = Readable.from([Buffer.from(inputContent)]);
    const encStream = createNodeEncryptStream({ encryptionKeys: key.publicKey });

    const encChunks: Buffer[] = [];
    encStream.on('data', (chunk) => encChunks.push(chunk));

    await pipeline(source, encStream);
    const encryptedBuffer = Buffer.concat(encChunks);
    expect(encryptedBuffer.length).toBeGreaterThan(0);

    // Decrypt pipeline
    const encSource = Readable.from([encryptedBuffer]);
    const decStream = createNodeDecryptStream({ decryptionKeys: key.privateKey });

    const decChunks: Buffer[] = [];
    decStream.on('data', (chunk) => decChunks.push(chunk));

    await pipeline(encSource, decStream);
    const decryptedOutput = Buffer.concat(decChunks).toString('utf-8');
    expect(decryptedOutput).toBe(inputContent);
  }, 15000);
});
