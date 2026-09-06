import { Message } from '../message/message.js';
import { CleartextMessage } from '../message/cleartext-message.js';

export interface CreateMessageOptions {
  text?: string;
  binary?: Uint8Array;
  filename?: string;
  date?: Date;
}

export interface ReadMessageOptions {
  armoredMessage?: string;
  binaryMessage?: Uint8Array;
}

export async function createMessage(options: CreateMessageOptions): Promise<Message> {
  if (options.text !== undefined) {
    return Message.fromText(options.text, options.filename, options.date);
  }
  if (options.binary !== undefined) {
    return Message.fromBinary(options.binary, options.filename, options.date);
  }
  throw new Error('createMessage requires either text or binary option');
}

export async function readMessage(options: ReadMessageOptions): Promise<Message> {
  if (options.armoredMessage) {
    return Message.read(options.armoredMessage);
  }
  if (options.binaryMessage) {
    return Message.read(options.binaryMessage);
  }
  throw new Error('readMessage requires either armoredMessage or binaryMessage option');
}

export async function createCleartextMessage(options: { text: string }): Promise<CleartextMessage> {
  return CleartextMessage.fromText(options.text);
}

export async function readCleartextMessage(options: { armoredMessage?: string; cleartext?: string }): Promise<CleartextMessage> {
  const input = options.armoredMessage ?? options.cleartext;
  if (!input) {
    throw new Error('readCleartextMessage requires armoredMessage or cleartext option');
  }
  return CleartextMessage.read(input);
}
