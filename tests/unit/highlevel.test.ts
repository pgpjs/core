import { describe, it, expect } from "vitest";
import PGPJS, { Key, createKeyStore, findKey } from "../../packages/core/src/index.js";

describe("High-Level PGPJS APIs (Developer Experience)", () => {
  it("generates an RFC 9580 key pair with generateKey()", async () => {
    const keys = await PGPJS.generateKey({
      name: "Developer Alice",
      email: "alice@example.com"
    });

    expect(keys.publicKey).toBeInstanceOf(Key);
    expect(keys.privateKey).toBeInstanceOf(Key);
    expect(keys.publicKey.getUserIDs()[0]).toContain("Developer Alice");
  });

  it("seals and opens data seamlessly with PGPJS.seal() and PGPJS.open()", async () => {
    const alice = await PGPJS.generateKey({
      name: "Alice",
      email: "alice@example.com"
    });

    const payload = {
      user: "Bob",
      balance: 4200,
      roles: ["admin", "developer"],
      active: true
    };

    // Seal
    const sealed = await PGPJS.seal(payload, {
      to: alice.publicKey
    });

    expect(typeof sealed).toBe("string");
    expect(sealed).toContain("-----BEGIN PGP MESSAGE-----");

    // Open
    const opened = await PGPJS.open<typeof payload>(sealed, {
      privateKey: alice.privateKey
    });

    expect(opened).toEqual(payload);
    expect(opened.balance).toBe(4200);
    expect(opened.roles).toEqual(["admin", "developer"]);
  });

  it("seals with signature from sender and verifies on open", async () => {
    const alice = await PGPJS.generateKey({ name: "Alice", email: "alice@example.com" });
    const bob = await PGPJS.generateKey({ name: "Bob", email: "bob@example.com" });

    const message = "Highly confidential instruction";

    const sealed = await PGPJS.seal(message, {
      to: bob.publicKey,
      from: alice.privateKey
    });

    const opened = await PGPJS.open<string>(sealed, {
      privateKey: bob.privateKey,
      from: alice.publicKey
    });

    expect(opened).toBe(message);
  });

  it("encrypts and decrypts typed JSON via encryptJSON / decryptJSON", async () => {
    interface UserProfile {
      id: string;
      email: string;
      verified: boolean;
    }

    const keys = await PGPJS.generateKey({ name: "System" });
    const profile: UserProfile = { id: "usr_123", email: "usr@test.com", verified: true };

    const cipher = await PGPJS.encryptJSON(profile, { to: keys.publicKey });
    const decrypted = await PGPJS.decryptJSON<UserProfile>(cipher, { privateKey: keys.privateKey });

    expect(decrypted.id).toBe("usr_123");
    expect(decrypted.verified).toBe(true);
  });

  it("supports shorthand aliases on encrypt() and decrypt()", async () => {
    const keys = await PGPJS.generateKey({ name: "Charlie" });

    const ciphertext = await PGPJS.encrypt({
      text: "Shorthand syntax test",
      to: keys.publicKey
    });

    const res = await PGPJS.decrypt({
      message: ciphertext,
      privateKey: keys.privateKey
    });

    expect(res.text).toBe("Shorthand syntax test");
  });

  it("inspects a key and returns structured developer metadata", async () => {
    const keys = await PGPJS.generateKey({
      name: "Audit User",
      email: "audit@pgpjs.dev"
    });

    const info = await PGPJS.inspectKey(keys.publicKey);
    expect(info.fingerprint.length).toBeGreaterThan(0);
    expect(info.keyID.length).toBe(16);
    expect(info.algorithm).toBe("EdDSA");
    expect(info.users[0]).toContain("Audit User");
    expect(info.subkeys.length).toBeGreaterThan(0);
    expect(info.revoked).toBe(false);
  });

  it("stores and finds keys via KeyStore and findKey()", async () => {
    const store = await PGPJS.createKeyStore({ adapter: "memory" });
    const keys = await PGPJS.generateKey({ name: "Dave", email: "dave@example.com" });

    await store.add(keys.publicKey);

    const retrieved = await store.get(keys.publicKey.getKeyID());
    expect(retrieved).not.toBeNull();
    expect(retrieved?.getKeyID()).toBe(keys.publicKey.getKeyID());

    const byEmail = await store.get("dave@example.com");
    expect(byEmail).not.toBeNull();

    const found = await findKey({ email: "dave@example.com", store });
    expect(found?.getKeyID()).toBe(keys.publicKey.getKeyID());
  });

  it("enforces custom security policies with PGPJS.create()", async () => {
    const strictPGP = PGPJS.create({
      policy: {
        rejectExpiredKeys: true,
        allowLegacyAlgorithms: false
      }
    });

    expect(strictPGP.policy.allowLegacyAlgorithms).toBe(false);
  });
});
