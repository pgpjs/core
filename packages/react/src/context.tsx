import React, { createContext, useContext, useMemo, ReactNode } from 'react';
import { SymmetricKeyAlgorithm, HashAlgorithm, CompressionAlgorithm } from '@pgpjs/core';

export interface PGPConfig {
  defaultSymmetricAlgorithm?: SymmetricKeyAlgorithm;
  defaultHashAlgorithm?: HashAlgorithm;
  defaultCompression?: CompressionAlgorithm;
}

export interface PGPContextValue {
  config: PGPConfig;
}

const PGPContext = createContext<PGPContextValue>({
  config: {
    defaultSymmetricAlgorithm: SymmetricKeyAlgorithm.AES256,
    defaultHashAlgorithm: HashAlgorithm.SHA256,
    defaultCompression: CompressionAlgorithm.ZLIB
  }
});

export interface PGPProviderProps {
  config?: PGPConfig;
  children: ReactNode;
}

export const PGPProvider: React.FC<PGPProviderProps> = ({ config = {}, children }) => {
  const value = useMemo(
    () => ({
      config: {
        defaultSymmetricAlgorithm: config.defaultSymmetricAlgorithm ?? SymmetricKeyAlgorithm.AES256,
        defaultHashAlgorithm: config.defaultHashAlgorithm ?? HashAlgorithm.SHA256,
        defaultCompression: config.defaultCompression ?? CompressionAlgorithm.ZLIB
      }
    }),
    [config.defaultSymmetricAlgorithm, config.defaultHashAlgorithm, config.defaultCompression]
  );

  return <PGPContext.Provider value={value}>{children}</PGPContext.Provider>;
};

export function usePGP(): PGPContextValue {
  return useContext(PGPContext);
}
