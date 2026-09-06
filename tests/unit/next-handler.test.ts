import { describe, it, expect } from "vitest";
import PGPJS from "../../packages/core/src/index.js";
import { pgp } from "../../packages/next/src/server.js";

describe("@pgpjs/next Route Handler middleware (pgp())", () => {
  it("automatically decrypts request, calls handler, and returns response", async () => {
    // Generate server and client keys
    const serverKeys = await PGPJS.generateKey({ name: "Server", email: "server@app.com" });
    const clientKeys = await PGPJS.generateKey({ name: "Client", email: "client@app.com" });

    // Define Route Handler using pgp()
    const POST = pgp(
      async ({ data, sender }) => {
        expect(data).toEqual({ amount: 500, recipient: "Merchant" });
        expect(sender?.valid).toBe(true);
        return {
          status: "processed",
          transactionId: "tx_987654"
        };
      },
      {
        privateKey: serverKeys.privateKey,
        clientPublicKey: clientKeys.publicKey,
        requireSignature: true
      }
    );

    // Client seals request
    const clientPayload = { amount: 500, recipient: "Merchant" };
    const sealedBody = await PGPJS.seal(clientPayload, {
      to: serverKeys.publicKey,
      from: clientKeys.privateKey
    });

    const mockRequest = new Request("https://api.app.com/api/payment", {
      method: "POST",
      body: sealedBody as string,
      headers: { "Content-Type": "application/pgp-encrypted" }
    });

    // Invoke Route Handler
    const response = await POST(mockRequest);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("application/pgp-encrypted");

    // Client opens encrypted response
    const responseBody = await response.text();
    const result = await PGPJS.open(responseBody, {
      privateKey: clientKeys.privateKey,
      from: serverKeys.publicKey
    });

    expect(result).toEqual({
      status: "processed",
      transactionId: "tx_987654"
    });
  });

  it("rejects unsigned requests when requireSignature is true", async () => {
    const serverKeys = await PGPJS.generateKey({ name: "Server" });

    const POST = pgp(
      async ({ data }) => ({ ok: true }),
      {
        privateKey: serverKeys.privateKey,
        requireSignature: true
      }
    );

    // Client sends encrypted message WITHOUT signature
    const unsignedBody = await PGPJS.seal("Anonymous attack", {
      to: serverKeys.publicKey
    });

    const mockRequest = new Request("https://api.app.com/api/admin", {
      method: "POST",
      body: unsignedBody as string
    });

    const response = await POST(mockRequest);
    expect(response.status).toBe(401);
  });
});
