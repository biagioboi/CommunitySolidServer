import { packDidCommMessageWithReturn, unpackDidCommPackResponse } from '../../../src/util/DidCommUtil';

describe('DidCommUtil', (): void => {
  it('reads the encrypted message returned by Credo packMessageWithReturn.', (): void => {
    const encryptedMessage = { ciphertext: 'abc' };

    expect(unpackDidCommPackResponse({ encryptedMessage, sym_key: 'secret' })).toEqual({
      encryptedMessage,
      symKey: 'secret',
    });
  });

  it('keeps compatibility with envelope-based responses.', (): void => {
    const encryptedMessage = { ciphertext: 'legacy' };

    expect(unpackDidCommPackResponse({ envelope: encryptedMessage, symKey: 'legacy-secret' })).toEqual({
      encryptedMessage,
      symKey: 'legacy-secret',
    });
  });

  it('throws when the encrypted message is missing.', (): void => {
    expect((): void => {
      unpackDidCommPackResponse({ sym_key: 'secret' });
    }).toThrow('wallet.packWithReturn() returned no encrypted message. Expected `envelope` or `encryptedMessage`.');
  });

  it('throws when the symmetric key is missing.', (): void => {
    expect((): void => {
      unpackDidCommPackResponse({ envelope: { ciphertext: 'abc' } });
    }).toThrow('wallet.packWithReturn() returned no symmetric key.');
  });

  it('packs messages from wallet.packWithReturn envelope responses.', async(): Promise<void> => {
    const encryptedMessage = { ciphertext: 'abc' };
    const payload = {
      toJSON: jest.fn().mockReturnValue({ '@type': 'https://didcomm.org/basicmessage/1.0/message' }),
    };
    const wallet = {
      pack: jest.fn(),
      packWithReturn: jest.fn().mockResolvedValue({
        envelope: encryptedMessage,
        sym_key: 'secret',
      }),
    };

    await expect(packDidCommMessageWithReturn(
      {
        config: {
          useDidSovPrefixWhereAllowed: false,
        },
        wallet,
      },
      payload,
      {
        recipientKeys: [ { publicKeyBase58: 'recipient-key' } ],
        routingKeys: [],
        senderKey: null,
      },
    )).resolves.toEqual({
      encryptedMessage,
      symKey: 'secret',
    });

    expect(wallet.packWithReturn).toHaveBeenCalledWith(
      { '@type': 'https://didcomm.org/basicmessage/1.0/message' },
      [ 'recipient-key' ],
      undefined,
    );
  });
});
