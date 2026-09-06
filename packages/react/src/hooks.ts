import { useState, useEffect, useCallback } from 'react';
import {
  Key,
  generateKeyPair,
  readKey,
  encrypt,
  decrypt,
  sign,
  verify,
  GenerateKeyPairOptions,
  KeyPairResult,
  EncryptOptions,
  DecryptOptions,
  DecryptResult,
  SignOptions,
  VerifyOptions,
  VerifyResult
} from '@pgpjs/core';
import { usePGP } from './context.js';

export function useKey(options: { armoredKey?: string; binaryKey?: Uint8Array } = {}) {
  const [key, setKey] = useState<Key | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);

  const loadKey = useCallback(async () => {
    if (!options.armoredKey && !options.binaryKey) {
      setKey(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const parsed = await readKey({
        armoredKey: options.armoredKey,
        binaryKey: options.binaryKey
      });
      setKey(parsed);
    } catch (err: any) {
      setError(err);
      setKey(null);
    } finally {
      setLoading(false);
    }
  }, [options.armoredKey, options.binaryKey]);

  useEffect(() => {
    loadKey();
  }, [loadKey]);

  return { key, loading, error, reload: loadKey };
}

export function useKeyGeneration() {
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);
  const [result, setResult] = useState<KeyPairResult | null>(null);

  const generate = useCallback(async (options: GenerateKeyPairOptions): Promise<KeyPairResult> => {
    setIsGenerating(true);
    setError(null);
    try {
      const kp = await generateKeyPair(options);
      setResult(kp);
      return kp;
    } catch (err: any) {
      setError(err);
      throw err;
    } finally {
      setIsGenerating(false);
    }
  }, []);

  return { generate, isGenerating, error, result };
}

export function useEncryption() {
  const { config } = usePGP();
  const [isEncrypting, setIsEncrypting] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);
  const [result, setResult] = useState<string | Uint8Array | null>(null);

  const executeEncrypt = useCallback(
    async (options: EncryptOptions): Promise<string | Uint8Array> => {
      setIsEncrypting(true);
      setError(null);
      try {
        const out = await encrypt({
          symmetricAlgorithm: config.defaultSymmetricAlgorithm,
          compression: config.defaultCompression,
          ...options
        });
        setResult(out);
        return out;
      } catch (err: any) {
        setError(err);
        throw err;
      } finally {
        setIsEncrypting(false);
      }
    },
    [config]
  );

  return { encrypt: executeEncrypt, isEncrypting, error, result };
}

export function useDecryption() {
  const [isDecrypting, setIsDecrypting] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);
  const [result, setResult] = useState<DecryptResult | null>(null);

  const executeDecrypt = useCallback(async (options: DecryptOptions): Promise<DecryptResult> => {
    setIsDecrypting(true);
    setError(null);
    try {
      const out = await decrypt(options);
      setResult(out);
      return out;
    } catch (err: any) {
      setError(err);
      throw err;
    } finally {
      setIsDecrypting(false);
    }
  }, []);

  return { decrypt: executeDecrypt, isDecrypting, error, result };
}

export function useSign() {
  const { config } = usePGP();
  const [isSigning, setIsSigning] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);
  const [result, setResult] = useState<string | Uint8Array | null>(null);

  const executeSign = useCallback(
    async (options: SignOptions): Promise<string | Uint8Array> => {
      setIsSigning(true);
      setError(null);
      try {
        const out = await sign({
          hashAlgorithm: config.defaultHashAlgorithm,
          ...options
        });
        setResult(out);
        return out;
      } catch (err: any) {
        setError(err);
        throw err;
      } finally {
        setIsSigning(false);
      }
    },
    [config]
  );

  return { sign: executeSign, isSigning, error, result };
}

export function useVerify() {
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);
  const [result, setResult] = useState<VerifyResult | null>(null);

  const executeVerify = useCallback(async (options: VerifyOptions): Promise<VerifyResult> => {
    setIsVerifying(true);
    setError(null);
    try {
      const out = await verify(options);
      setResult(out);
      return out;
    } catch (err: any) {
      setError(err);
      throw err;
    } finally {
      setIsVerifying(false);
    }
  }, []);

  return { verify: executeVerify, isVerifying, error, result };
}
