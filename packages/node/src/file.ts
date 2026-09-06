import * as fs from 'node:fs/promises';
import {
  encrypt,
  decrypt,
  sign,
  verify,
  DecryptOptions,
  DecryptResult,
  EncryptOptions,
  SignOptions,
  VerifyOptions,
  VerifyResult
} from '@pgpjs/core';

export async function encryptFile(
  inputPath: string,
  outputPath: string,
  options: Omit<EncryptOptions, 'message'>
): Promise<void> {
  const content = await fs.readFile(inputPath);
  const encrypted = await encrypt({
    ...options,
    message: new Uint8Array(content)
  });

  if (typeof encrypted === 'string') {
    await fs.writeFile(outputPath, encrypted, 'utf-8');
  } else {
    await fs.writeFile(outputPath, encrypted);
  }
}

export async function decryptFile(
  inputPath: string,
  outputPath: string,
  options: Omit<DecryptOptions, 'message'>
): Promise<DecryptResult> {
  const content = await fs.readFile(inputPath);
  const result = await decrypt({
    ...options,
    message: new Uint8Array(content)
  });

  await fs.writeFile(outputPath, result.data);
  return result;
}

export async function signFile(
  inputPath: string,
  outputPath: string,
  options: Omit<SignOptions, 'message'>
): Promise<void> {
  const content = await fs.readFile(inputPath);
  const signature = await sign({
    ...options,
    message: new Uint8Array(content)
  });

  if (typeof signature === 'string') {
    await fs.writeFile(outputPath, signature, 'utf-8');
  } else {
    await fs.writeFile(outputPath, signature);
  }
}

export async function verifyFile(
  inputPath: string,
  signaturePath: string,
  options: Omit<VerifyOptions, 'message' | 'signature'>
): Promise<VerifyResult> {
  const content = await fs.readFile(inputPath);
  const signature = await fs.readFile(signaturePath, 'utf-8');

  return verify({
    ...options,
    message: new Uint8Array(content),
    signature
  });
}
