import type { EncryptedMessage } from '@credo-ts/core';
import { ForwardMessage } from '@credo-ts/core/build/modules/routing/messages/ForwardMessage';

export type MutableEncryptedMessage = EncryptedMessage & {
  hash?: string;
  signatureFromCSS?: unknown;
  hashCredential?: unknown;
};

export interface DidCommEncryptionKey {
  publicKeyBase58: string;
}

export interface DidCommEnvelopeKeys {
  recipientKeys: DidCommEncryptionKey[];
  routingKeys: DidCommEncryptionKey[];
  senderKey: DidCommEncryptionKey | null;
}

export interface DidCommPackableMessage {
  toJSON(options: { useDidSovPrefixWhereAllowed: boolean }): Record<string, unknown>;
}

export interface DidCommAgentContext {
  config: {
    useDidSovPrefixWhereAllowed: boolean;
  };
  wallet: {
    pack(
      payload: Record<string, unknown>,
      recipientKeys: string[],
      senderVerkey?: string,
    ): Promise<EncryptedMessage>;
    packWithReturn(
      payload: Record<string, unknown>,
      recipientKeys: string[],
      senderVerkey?: string,
    ): Promise<unknown>;
  };
}

interface PackedMessageWithReturnResponse {
  encryptedMessage?: MutableEncryptedMessage;
  envelope?: MutableEncryptedMessage;
  sym_key?: unknown;
  symKey?: unknown;
}

export interface PackedDidCommMessage {
  encryptedMessage: MutableEncryptedMessage;
  symKey: unknown;
}

export function unpackDidCommPackResponse(response: unknown): PackedDidCommMessage {
  const packedResponse = response as PackedMessageWithReturnResponse | null | undefined;
  const encryptedMessage = packedResponse?.encryptedMessage ?? packedResponse?.envelope;
  const symKey = packedResponse?.sym_key ?? packedResponse?.symKey;

  if (encryptedMessage === undefined || encryptedMessage === null || typeof encryptedMessage !== 'object') {
    throw new Error('wallet.packWithReturn() returned no encrypted message. Expected `envelope` or `encryptedMessage`.');
  }

  if (symKey === undefined) {
    throw new Error('wallet.packWithReturn() returned no symmetric key.');
  }

  return {
    encryptedMessage,
    symKey,
  };
}

export async function packDidCommMessageWithReturn(
  agentContext: DidCommAgentContext,
  payload: DidCommPackableMessage,
  keys: DidCommEnvelopeKeys,
): Promise<PackedDidCommMessage> {
  const { recipientKeys, routingKeys, senderKey } = keys;
  let recipientKeysBase58 = recipientKeys.map((key): string => key.publicKeyBase58);
  const routingKeysBase58 = routingKeys.map((key): string => key.publicKeyBase58);
  const senderKeyBase58 = senderKey?.publicKeyBase58;
  const message = payload.toJSON({
    useDidSovPrefixWhereAllowed: agentContext.config.useDidSovPrefixWhereAllowed,
  });

  const packedResponse = await agentContext.wallet.packWithReturn(
    message,
    recipientKeysBase58,
    senderKeyBase58 ?? undefined,
  );
  let { encryptedMessage, symKey } = unpackDidCommPackResponse(packedResponse);

  for (const routingKeyBase58 of routingKeysBase58) {
    const forwardMessage = new ForwardMessage({
      to: recipientKeysBase58[0],
      message: encryptedMessage,
    });
    recipientKeysBase58 = [ routingKeyBase58 ];
    const forwardJson = forwardMessage.toJSON({
      useDidSovPrefixWhereAllowed: agentContext.config.useDidSovPrefixWhereAllowed,
    });
    encryptedMessage = await agentContext.wallet.pack(
      forwardJson,
      [ routingKeyBase58 ],
      undefined,
    ) as MutableEncryptedMessage;
  }

  return { encryptedMessage, symKey };
}
