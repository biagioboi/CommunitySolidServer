import {AskarModule} from '@credo-ts/askar';
import {
  Agent,
  AutoAcceptCredential,
  AutoAcceptProof,
  BasicMessage,
  BasicMessageEventTypes,
  ConnectionEventTypes,
  ConnectionRecord,
  ConnectionsModule,
  ConsoleLogger,
  CredentialsModule,
  DidCommV1Service,
  DidDocumentBuilder,
  DidExchangeState,
  DidKey,
  DifPresentationExchangeProofFormatService,
  getEd25519VerificationKey2018,
  getJwkFromKey,
  HttpOutboundTransport,
  isDid,
  JsonLdCredentialFormatService,
  JwsService,
  Key,
  KeyType,
  LogLevel,
  ProofsModule,
  TypedArrayEncoder,
  V2CredentialProtocol,
  V2ProofProtocol,
  W3cCredentialsModule,
} from '@credo-ts/core';
import {agentDependencies, HttpInboundTransport} from '@credo-ts/node';
import {ariesAskar} from '@hyperledger/aries-askar-nodejs';
import {getLoggerFor} from '../logging/LogUtil';
import {Initializer} from './Initializer';
import {VcAuthorizingHttpHandler} from "../server/VcAuthorizingHttpHandler";
import {guardedStreamFrom, readableToString} from "../util/StreamUtil";
import {HttpRequest} from "../server/HttpRequest";
import {RequestParser} from '../http/input/RequestParser';
import {HttpResponse} from "../server/HttpResponse";
import {EnvelopeService} from "@credo-ts/core/build/agent/EnvelopeService";
import {sha256} from "js-sha256";

/**
 * A class that can be used to instantiate and start a server based on a Component.js configuration.
 */



export interface AgentInitializerArgs {
  operationHandler: VcAuthorizingHttpHandler;
  requestParser: RequestParser;
}
export class AgentInitializer extends Initializer {
  protected readonly logger = getLoggerFor(this);
  public agent: Agent;
  public did: string;
  public ttpKey: any;
  public lastKeyForMsgEncryption: Record<string, any>;
  public operationHandler: VcAuthorizingHttpHandler;
  private readonly requestParser: RequestParser;

  public constructor(args: AgentInitializerArgs) {
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
    this.did = 'did:web:raw.githubusercontent.com:biagioboi:CommunitySolidServer:main';
    this.ttpKey = Key.fromPublicKeyBase58('67ZL6vtGGuwhNpsghbArGPzttsnC3bCov7CSHq4i1w5K', KeyType.Ed25519);
    this.lastKeyForMsgEncryption = {};
    this.operationHandler = args.operationHandler;
    this.requestParser = args.requestParser;
  }

  /**
     * A class that can be used to instantiate and start a server based on a Component.js configuration.
     */

  public async sendTheProof(options: any) {
    this.agent.events.on(ConnectionEventTypes.ConnectionStateChanged, async ({ payload}) => {
      /* If you want, I can generate also a more professional VPR, using the agent */
      const connRecord: ConnectionRecord = payload.connectionRecord as ConnectionRecord;
      if (connRecord.state === DidExchangeState.Completed) {
        await this.agent.proofs.requestProof({
          connectionId: connRecord.id,
          protocolVersion: 'v2',
          proofFormats: {
            presentationExchange: {
              '@context': [ 'https://bboi.solidcommunity.net/public/schemas/2024/presexchange.jsonld' ],
              type: [ 'VerifiablePresentationRequest' ],
              presentationDefinition: {
                id: '32f54163-7166-48f1-93d8-ff217bdb0653',
                input_descriptors: [
                  {
                    id: 'unisa_student',
                    name: 'University of Salerno Demo',
                    purpose: 'Demonstrate to be a student from the University of Salerno to access this POD',
                    constraints: {
                      fields: [
                        {
                          path: [
                            '$.credentialSubject.degree',
                            '$.credentialSubject.claims.degree',
                          ],
                        },
                      ],
                    },
                  },
                ],
                format: { // Which format we want for the signature? Currently, we are using ldp_vp
                  ldp_vc: {
                    proof_type: [
                      'JsonWebSignature2020',
                      'Ed25519Signature2018',
                      'EcdsaSecp256k1Signature2019',
                      'RsaSignature2018',
                    ],
                  },
                  ldp_vp: {
                    proof_type: ['Ed25519Signature2018'],
                  },
                  ldp: {
                    proof_type: ['RsaSignature2018'],
                  },
                },
                requestACP: {
                  type: [ 'ACPContext' ],
                  target: options.acp.target,
                  owner: this.did,
                  issuer: options.acp.issuer,
                  client: options.acp.client,
                  agent: options.acp.agent,
                },
              },
              options: {
                challenge: options.challenge,
                domain: 'https://bboi.solidcommunity.net/definition/ourProtocol#test',
              },
              signPresentationRequest: false,

            },

          },
        });
        this.agent.events.off(ConnectionEventTypes.ConnectionStateChanged, () => {});
      }
    });
  }
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
    const did = this.did;
    // Initialize the agent
    await this.agent.initialize();

    this.agent.events.on(BasicMessageEventTypes.BasicMessageStateChanged, async (payload) => {
      const basicMessageRecord: any = payload.payload.basicMessageRecord;
      const connectionId: any = basicMessageRecord.connectionId;
      const msg: any = payload.payload.message!;
      const content = msg.content;
      const objWrappedVP = JSON.parse(content);
      if (objWrappedVP.type !== undefined && objWrappedVP.type[0] === 'VerifiablePresentation') {
        const requestUrl = objWrappedVP.wrappedVP.requestACP.target;
        const request = guardedStreamFrom([ ]) as HttpRequest;
        const urlParsed = new URL(requestUrl);
        request.method = 'GET';
        request.url = urlParsed.pathname;
        request.headers = {
          vp: JSON.stringify(objWrappedVP),
          accept: 'text/plain',
          'accept-language': 'en-gb, en;q=0.5',
          'content-type': 'text/plain',
          'if-unmodified-since': 'Wed, 21 Oct 2015 07:28:00 UTC',
          'if-none-match': '12345',
          'transfer-encoding': 'chunked',
          host: 'localhost:3000',
        };

        // Create a dummy request to get the requested file. This is somehow strange, we may start thinking to have a reader of the file, instead of complicating the life in this way.
        const operation = await this.requestParser.handle(request);
        operation.conditions = {
          matchesMetadata: (): boolean => true,
        };
        const response: HttpResponse = {} as any;
        const responseDescription = await this.operationHandler.handle({request, operation, response});
        const txtToCypher = await readableToString(responseDescription.data!);
        const envService = new EnvelopeService(new ConsoleLogger());
        const theMessage = new BasicMessage({ content: txtToCypher });

        let startTime:Date = new Date();
        const responseEncrypt: any = await envService.packMessageWithReturn(
            this.agent.context,
            theMessage,
            {
              recipientKeys: [ this.ttpKey ],
              routingKeys: [],
              senderKey: null,
            },
        );
        let endTime:Date = new Date();
        const milliDiff: number = startTime.getTime()
            - endTime.getTime();

        // get seconds
        this.logger.info(`Time elapsed ${ milliDiff } `)

        const encryptedMessage = responseEncrypt.envelope;
        encryptedMessage.hash = sha256(JSON.stringify(theMessage));
        this.lastKeyForMsgEncryption[encryptedMessage.hash] = responseEncrypt.sym_key;
        this.logger.info(`Sending encrypted message to the App, hash ${ encryptedMessage.hash } ...`);
        await this.agent.basicMessages.sendMessage(connectionId, JSON.stringify(encryptedMessage));
      } else if (objWrappedVP.signedResource !== undefined) {
        const jws = objWrappedVP.signedResource;
        const jwsService = new JwsService();
        const { isValid, signerKeys } = await jwsService.verifyJws(this.agent.context, {
          jws: {
            ...jws,
            payload: jws.payload,
          },
          jwkResolver: ({ jws: { header } }) => {
            if (typeof header.kid !== 'string' || !isDid(header.kid, 'key')) {
              throw new Error('JWS header kid must be a did:key DID.');
            }
            const didKey = DidKey.fromDid(header.kid);
            return getJwkFromKey(didKey.key);
          },
        });
        if (isValid) {
          this.logger.info(`Signature validated, sending symmetric key to the App ...`);
          const revertBasePayload = atob(objWrappedVP.signedResource.payload);
          const payloadJWSObject = JSON.parse(JSON.parse(revertBasePayload));
          await this.agent.basicMessages.sendMessage(connectionId, JSON.stringify({keyForDecrypt: this.lastKeyForMsgEncryption[payloadJWSObject['hash']]}));
        }
      }
    });

    try {
      const ed25519Key = await this.agent.wallet.createKey({
        keyType: KeyType.Ed25519,
        privateKey: TypedArrayEncoder.fromString('afjdemoverysercure00000000000013'),
      });

      this.logger.info(this.did);
      const builder = new DidDocumentBuilder(this.did);
      const ed25519VerificationMethod2020 = getEd25519VerificationKey2018({
        key: ed25519Key,
        id: `${this.did}#${ed25519Key.fingerprint}`,
        controller: this.did,
      });


      builder.addService(new DidCommV1Service({
        "id": "#inline-0",
        "serviceEndpoint": "http://localhost:3015",
        "recipientKeys": [`${this.did}#${ed25519Key.fingerprint}`],
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
      let created_dids = await this.agent.dids.getCreatedDids({method: 'web', did: this.did});
      console.log("This is the User Wallet, it has this DID: " + created_dids[0].did);

      /*const invitation = await fetch('http://localhost:8082/generateInvitation');
      const respJson = await invitation.json();
      const invitationUrl = respJson.url;
      const agentContext = this.agent.context;
      const conRecord = await this.agent.oob.receiveInvitationFromUrl(invitationUrl);
      const agentEventEmitter = this.agent.events;
      const transportService = new TransportService(agentContext, agentEventEmitter);
      this.ttpKey
      const sessionWithTTP = transportService.findSessionByConnectionId(conRecord.connectionRecord!.id)*/
    }
  }
}
