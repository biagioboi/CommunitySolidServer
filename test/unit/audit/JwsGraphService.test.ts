import { mkdtemp } from 'fs/promises';
import { remove, readdir } from 'fs-extra';
import { tmpdir } from 'os';
import { join } from 'path';
import { JwsGraphService } from '../../../src/audit/JwsGraphService';

describe('A JwsGraphService', (): void => {
  let rootFilePath: string;
  let service: JwsGraphService;

  beforeEach(async(): Promise<void> => {
    rootFilePath = await mkdtemp(join(tmpdir(), 'css-jws-graph-'));
    service = new JwsGraphService({ rootFilePath });
  });

  afterEach(async(): Promise<void> => {
    await remove(rootFilePath);
  });

  it('stores a verified JWS in the reserved graph space.', async(): Promise<void> => {
    const record = await service.storeVerifiedJws({
      connectionId: 'conn-1',
      jws: {
        header: { kid: 'did:key:z6Mkgd3DemoKey' },
        payload: 'payload-1',
        signature: 'signature-1',
      },
      messageHash: 'a'.repeat(64),
      requestedResource: 'http://example.com/private/report',
      requesterDid: 'did:web:alice.example',
    });

    expect(record.requestedResource).toBe('http://example.com/private/report');
    expect(record.requesterDid).toBe('did:web:alice.example');
    expect(record.signedResourceType).toBe('jws');
    expect(record.signedResource).toEqual(expect.objectContaining({
      payload: 'payload-1',
    }));
    expect(record.signerKid).toBe('did:key:z6Mkgd3DemoKey');

    const storedFiles = await readdir(join(rootFilePath, '.internal/jws-audit/records'));
    expect(storedFiles).toHaveLength(1);
  });

  it('stores a verified NRR VC in the reserved graph space.', async(): Promise<void> => {
    const record = await service.storeVerifiedJws({
      connectionId: 'conn-vc-1',
      messageHash: 'c'.repeat(64),
      requestedResource: 'http://example.com/private/report',
      requesterDid: 'did:web:alice.example',
      signedResource: {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://secureapp.solidcommunity.net/public/NonRepudiationContext.jsonld',
        ],
        type: [ 'VerifiableCredential', 'NonRepudiationDestination' ],
        issuer: 'did:web:secureapp.solidcommunity.net:public',
        credentialSubject: {
          id: 'did:web:alice.example',
          requestedResource: 'http://example.com/private/report',
          signedHash: 'c'.repeat(64),
        },
        proof: {
          verificationMethod: 'did:web:secureapp.solidcommunity.net:public#key-1',
        },
      },
      signedResourceType: 'vc',
      signerId: 'did:web:secureapp.solidcommunity.net:public#key-1',
    });

    expect(record.signedResourceType).toBe('vc');
    expect(record.signerId).toBe('did:web:secureapp.solidcommunity.net:public#key-1');
    expect(record.signedResource).toEqual(expect.objectContaining({
      issuer: 'did:web:secureapp.solidcommunity.net:public',
    }));
    expect(record.jws).toBeUndefined();
    expect(record.signerKid).toBeUndefined();
  });

  it('filters stored JWS records by resource and requester DID.', async(): Promise<void> => {
    await service.storeVerifiedJws({
      connectionId: 'conn-1',
      jws: {
        header: { kid: 'did:key:z6MkResourceOne' },
        payload: 'payload-1',
        signature: 'signature-1',
      },
      messageHash: 'a'.repeat(64),
      requestedResource: 'http://example.com/private/report',
      requesterDid: 'did:web:alice.example',
    });

    await service.storeVerifiedJws({
      connectionId: 'conn-2',
      jws: {
        header: { kid: 'did:key:z6MkResourceTwo' },
        payload: 'payload-2',
        signature: 'signature-2',
      },
      messageHash: 'b'.repeat(64),
      requestedResource: 'http://example.com/private/other',
      requesterDid: 'did:web:bob.example',
    });

    await expect(service.findVerifiedJws({
      requestedResource: 'http://example.com/private/report',
    })).resolves.toEqual(expect.arrayContaining([
      expect.objectContaining({
        requestedResource: 'http://example.com/private/report',
        requesterDid: 'did:web:alice.example',
      }),
    ]));

    await expect(service.findVerifiedJws({
      requesterDid: 'did:web:bob.example',
    })).resolves.toEqual([
      expect.objectContaining({
        requestedResource: 'http://example.com/private/other',
        requesterDid: 'did:web:bob.example',
      }),
    ]);
  });
});
