import { describe, it, expect } from 'vitest';
import {
  armor,
  dearmor,
  isArmored,
  formatCleartextSignedMessage,
  parseCleartextSignedMessage,
  canonicalizeCleartext
} from '../../packages/core/src/armor/index.js';
import { ArmorType, HashAlgorithm } from '../../packages/core/src/types/enums.js';
import { utf8ToBytes, bytesToUtf8 } from '../../packages/core/src/utils/bytes.js';
import { PGPParseError } from '../../packages/core/src/errors/index.js';

describe('ASCII Armor', () => {
  it('armors and dearmors binary message roundtrip', () => {
    const data = utf8ToBytes('Hello OpenPGP ASCII Armor!');
    const armored = armor(ArmorType.Message, data, { Version: 'PGPJS 0.1' });

    expect(isArmored(armored)).toBe(true);
    expect(armored).toContain('-----BEGIN PGP MESSAGE-----');
    expect(armored).toContain('-----END PGP MESSAGE-----');
    expect(armored).toContain('Version: PGPJS 0.1');

    const dearmored = dearmor(armored);
    expect(dearmored.type).toBe(ArmorType.Message);
    expect(dearmored.headers.Version).toBe('PGPJS 0.1');
    expect(bytesToUtf8(dearmored.data)).toBe('Hello OpenPGP ASCII Armor!');
  });

  it('rejects tampered CRC in armored message', () => {
    const data = utf8ToBytes('Test data');
    const armored = armor(ArmorType.Message, data);
    // Tamper with CRC line
    const tampered = armored.replace(/=[A-Za-z0-9+/]{4}/, '=AAAA');
    expect(() => dearmor(tampered)).toThrow(PGPParseError);
  });
});

describe('Cleartext Signed Messages', () => {
  it('formats and parses cleartext messages with dash-escaping', () => {
    const originalText = 'Hello,\n- This line starts with a dash.\n-- Two dashes.\nRegular line.';
    const fakeSigArmor = '-----BEGIN PGP SIGNATURE-----\r\nVersion: 1.0\r\n\r\n=1234\r\n-----END PGP SIGNATURE-----';

    const formatted = formatCleartextSignedMessage(originalText, fakeSigArmor, HashAlgorithm.SHA256);
    expect(formatted).toContain('- - This line starts with a dash.');
    expect(formatted).toContain('- -- Two dashes.');

    const parsed = parseCleartextSignedMessage(formatted);
    expect(parsed.text).toBe(originalText);
    expect(parsed.hashAlgorithm).toBe(HashAlgorithm.SHA256);
    expect(parsed.signatureArmor.trim()).toBe(fakeSigArmor.trim());
  });

  it('canonicalizes trailing whitespace and CRLF', () => {
    const text = 'Line 1   \nLine 2\t\r\nLine 3';
    const canonical = canonicalizeCleartext(text);
    expect(canonical).toBe('Line 1\r\nLine 2\r\nLine 3');
  });
});
