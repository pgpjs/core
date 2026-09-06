import { Key } from "../key/key.js";
import { KeyStore } from "../store/index.js";

export type KeyResolver = (query: { email?: string; keyID?: string; fingerprint?: string }) => Promise<Key | null>;

export interface FindKeyOptions {
  email?: string;
  keyID?: string;
  fingerprint?: string;
  store?: KeyStore;
  resolvers?: KeyResolver[];
}

export async function findKey(options: FindKeyOptions): Promise<Key | null> {
  // 1. Check local key store if provided
  if (options.store) {
    const id = options.fingerprint ?? options.keyID ?? options.email;
    if (id) {
      const found = await options.store.get(id);
      if (found) return found;
    }
  }

  // 2. Custom resolvers
  if (options.resolvers) {
    for (const resolver of options.resolvers) {
      try {
        const found = await resolver(options);
        if (found) return found;
      } catch {
        // continue
      }
    }
  }

  return null;
}
