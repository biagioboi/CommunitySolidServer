import { AskarModule } from '@credo-ts/askar';
import {
  Agent,
  AutoAcceptCredential,
  AutoAcceptProof,
  ConnectionsModule,
  CredentialsModule, DidCommV1Service,
  DidDocumentBuilder,
  DifPresentationExchangeProofFormatService, getEd25519VerificationKey2018,
  getEd25519VerificationKey2020,
  HttpOutboundTransport,
  JsonLdCredentialFormatService,
  KeyType,
  ProofsModule,
  TypedArrayEncoder,
  V2CredentialProtocol,
  V2ProofProtocol,
  W3cCredentialsModule,
} from '@credo-ts/core';
import { agentDependencies, HttpInboundTransport } from '@credo-ts/node';
import { ariesAskar } from '@hyperledger/aries-askar-nodejs';
import { getLoggerFor } from '../logging/LogUtil';
import { Initializer } from './Initializer';

/**
 * A class that can be used to instantiate and start a server based on a Component.js configuration.
 */
export class AgentInitializer extends Initializer {
  protected readonly logger = getLoggerFor(this);
  public agent: Agent;

  public constructor() {
    super();
    this.agent = new Agent({
      config: {
        label: 'SecureSolidApplication',
        walletConfig: {
          id: 'CommunitySolidServerSecure',
          key: 'solidserver000000000000000000010',
        },
        endpoints: [ 'http://localhost:3015' ],
        autoUpdateStorageOnStartup: true,
      },
      dependencies: agentDependencies,
      modules: {
        connections: new ConnectionsModule({
          autoAcceptConnections: true,
        }),
        credentials: new CredentialsModule({
          autoAcceptCredentials: AutoAcceptCredential.Never,
          credentialProtocols: [
            new V2CredentialProtocol({
              credentialFormats: [
                new JsonLdCredentialFormatService(),
              ],
            }),
          ],
        }),
        proofs: new ProofsModule({
          autoAcceptProofs: AutoAcceptProof.ContentApproved,
          proofProtocols: [
            new V2ProofProtocol({
              proofFormats: [
                new DifPresentationExchangeProofFormatService(),
              ],
            }),
          ],
        }),
        w3cCredentials: new W3cCredentialsModule(),
        askar: new AskarModule({
          ariesAskar,
        }),
      },
    });
  }

  /**
     * A class that can be used to instantiate and start a server based on a Component.js configuration.
     */
  public async handle(): Promise<void> {
    /* Function that generate the agent */
    this.logger.info('Trying to initialize');
    await this.initializeIssuerAgent();
  }

  // The DID used by this wallet is did:key:z6MkhnfPNoDFRu7ChY1u8d2zoJJv9Un9Br1KhHAyaBawnh5c
  private async initializeIssuerAgent(): Promise<void> {
    // Register a simple `Http` outbound transport
    this.agent.registerOutboundTransport(new HttpOutboundTransport());

    // Register a simple `Http` inbound transport
    this.agent.registerInboundTransport(new HttpInboundTransport({ port: 3015 }));

    // Initialize the agent
    await this.agent.initialize();
    const did = `did:web:raw.githubusercontent.com:biagioboi:CommunitySolidServer:main`;

    try {
      const ed25519Key = await this.agent.wallet.createKey({
        keyType: KeyType.Ed25519,
        privateKey: TypedArrayEncoder.fromString('afjdemoverysercure00000000000013'),
      });

      this.logger.info(did);
      const builder = new DidDocumentBuilder(did);
      const ed25519VerificationMethod2020 = getEd25519VerificationKey2018({
        key: ed25519Key,
        id: `${did}#${ed25519Key.fingerprint}`,
        controller: did,
      });


      builder.addService(new DidCommV1Service({
        "id": "#inline-0",
        "serviceEndpoint": "http://localhost:3015",
        "recipientKeys": [`${did}#${ed25519Key.fingerprint}`],
        "routingKeys": []
      }));

      builder.addVerificationMethod(ed25519VerificationMethod2020);
      builder.addAuthentication(ed25519VerificationMethod2020.id);
      builder.addAssertionMethod(ed25519VerificationMethod2020.id);
      console.log(JSON.stringify(builder.build()));

      await this.agent.dids.import({
        did,
        didDocument: builder.build(),
        privateKeys: [{
          keyType: KeyType.Ed25519,
          privateKey: TypedArrayEncoder.fromString('afjdemoverysercure00000000000013'),
        }],
      });
    } catch {
      const didResp:any = await this.agent.dids.resolve(did);
      await this.agent.dids.resolveDidDocument(did);

      await this.agent.dids.update({
        did,
        didDocument: didResp.didDocument,
        overwrite: true,
        options: {
          keyType: KeyType.Ed25519,
          privateKey: TypedArrayEncoder.fromString('afjdemoverysercure10000000008002')
        }
      });
      let created_dids = await this.agent.dids.getCreatedDids({method: 'web', did: did});
      console.log("This is the User Wallet, it has this DID: " + created_dids[0].did);
    }
  }
}
