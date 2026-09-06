export class PGPError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PGPError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class PGPParseError extends PGPError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PGPParseError';
  }
}

export class PGPKeyError extends PGPError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PGPKeyError';
  }
}

export class PGPEncryptionError extends PGPError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PGPEncryptionError';
  }
}

export class PGPDecryptionError extends PGPError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PGPDecryptionError';
  }
}

export class PGPSignatureError extends PGPError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PGPSignatureError';
  }
}

export class PGPVerificationError extends PGPError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PGPVerificationError';
  }
}

export class PGPAlgorithmError extends PGPError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PGPAlgorithmError';
  }
}
