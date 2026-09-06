import { Key } from "../key/key.js";
import { readKey } from "../key/key-management.js";

export interface KeyStore {
  add(key: Key | string): Promise<void>;
  get(identifier: string): Promise<Key | null>;
  list(): Promise<Key[]>;
  remove(identifier: string): Promise<boolean>;
}

export class MemoryKeyStore implements KeyStore {
  private keys: Map<string, Key> = new Map();

  async add(key: Key | string): Promise<void> {
    const k = typeof key === "string" ? await readKey({ armoredKey: key }) : key;
    this.keys.set(k.getFingerprint().toLowerCase(), k);
    this.keys.set(k.getKeyID().toLowerCase(), k);
    for (const user of k.getUserIDs()) {
      this.keys.set(user.toLowerCase(), k);
      const match = user.match(/<([^>]+)>/);
      if (match) {
        this.keys.set(match[1].toLowerCase(), k);
      }
    }
  }

  async get(identifier: string): Promise<Key | null> {
    return this.keys.get(identifier.toLowerCase()) ?? null;
  }

  async list(): Promise<Key[]> {
    const unique = new Set<Key>(this.keys.values());
    return Array.from(unique);
  }

  async remove(identifier: string): Promise<boolean> {
    const key = await this.get(identifier);
    if (!key) return false;
    this.keys.delete(key.getFingerprint().toLowerCase());
    this.keys.delete(key.getKeyID().toLowerCase());
    return true;
  }
}

export interface KeyStoreOptions {
  adapter?: "memory" | "indexeddb" | "filesystem" | "custom";
  store?: KeyStore;
}

export async function createKeyStore(options: KeyStoreOptions = {}): Promise<KeyStore> {
  if (options.store) return options.store;
  // Defaults to in-memory key store
  return new MemoryKeyStore();
}
