import { describe, it, expect } from 'vitest';
import React from 'react';
import { PGPProvider, usePGP } from '../../packages/react/src/index.js';
import { SymmetricKeyAlgorithm } from '@pgpjs/core';

describe('@pgpjs/react components and hooks', () => {
  it('creates PGPProvider component element', () => {
    const element = React.createElement(
      PGPProvider,
      {
        config: {
          defaultSymmetricAlgorithm: SymmetricKeyAlgorithm.AES128
        }
      },
      React.createElement('div', null, 'PGP Child')
    );

    expect(element).toBeDefined();
    expect(element.type).toBe(PGPProvider);
    expect(element.props.config?.defaultSymmetricAlgorithm).toBe(SymmetricKeyAlgorithm.AES128);
  });
});
