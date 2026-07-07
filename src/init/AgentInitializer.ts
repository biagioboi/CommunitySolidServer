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
  isDid, JsonEncoder,
  JsonLdCredentialFormatService, JwaSignatureAlgorithm,
  JwsService, JwtPayload,
  Key,
  KeyType,
  LogLevel,
  ProofsModule,
  TypedArrayEncoder,
  V2CredentialProtocol,
  V2ProofProtocol,
  W3cCredentialsModule, SignatureSuiteRegistry, getKeyFromVerificationMethod,
  W3cJsonLdVerifiableCredential,
} from '@credo-ts/core';
import type { BaseEvent, BasicMessageStateChangedEvent, ConnectionStateChangedEvent } from '@credo-ts/core';
import {agentDependencies, HttpInboundTransport} from '@credo-ts/node';
import {ariesAskar} from '@hyperledger/aries-askar-nodejs';
import {getLoggerFor} from '../logging/LogUtil';
import {Initializer} from './Initializer';
import {VcAuthorizingHttpHandler} from "../server/VcAuthorizingHttpHandler";
import {guardedStreamFrom, readableToString} from "../util/StreamUtil";
import {HttpRequest} from "../server/HttpRequest";
import {RequestParser} from '../http/input/RequestParser';
import {HttpResponse} from "../server/HttpResponse";
import {sha256} from "js-sha256";
import type { JwsGraphService } from '../audit/JwsGraphService';

import {createWalletKeyPairClass} from "@credo-ts/core/build/crypto/WalletKeyPair";
const vc: any = require('@digitalcredentials/vc'); // Replace `any` with specific types if known





import {stringToBytes} from "did-jwt/lib/util";
import utils_1 from "../../package/build/utils";
import JsonEncoder_1 from "../../package/build/utils/JsonEncoder";
import {defaultDocumentLoader} from "@credo-ts/core/build/modules/vc/data-integrity/libraries/documentLoader";
import type { MutableEncryptedMessage } from '../util/DidCommUtil';
import { packDidCommMessageWithReturn } from '../util/DidCommUtil';
import fetch from 'cross-fetch';

/**
 * A class that can be used to instantiate and start a server based on a Component.js configuration.
 */



export interface AgentInitializerArgs {
  operationHandler: VcAuthorizingHttpHandler;
  requestParser: RequestParser;
  jwsGraphService: JwsGraphService;
  ttpInvitationEndpoint?: string;
}

interface PendingSignedResourceContext {
  connectionId: string;
  messageHash: string;
  requestedResource: string;
  requesterDid: string;
}

interface ProofRequestOptions {
  outOfBandId: string;
  challenge: string;
  acp: {
    target: string;
    issuer: string;
    client: string;
    agent: string;
  };
}

interface VerifiedSignedResourceResult {
  messageHash: string;
  requestedResource?: string;
  requesterDid?: string;
  signedResource: Record<string, unknown>;
  signedResourceType: 'jws' | 'vc';
  signerId?: string;
}

const DEFAULT_TTP_INVITATION_ENDPOINT = 'http://demo-ttp:8082/generateInvitation';
const DEFAULT_TTP_CONNECTION_TIMEOUT_MS = 20_000;

export class AgentInitializer extends Initializer {
  protected readonly logger = getLoggerFor(this);
  public agent: Agent;
  public did: string;
  public lastKeyForMsgEncryption: Record<string, any>;
  public operationHandler: VcAuthorizingHttpHandler;
  private readonly requestParser: RequestParser;
  private readonly jwsGraphService: JwsGraphService;
  private readonly pendingSignedResourceContexts: Map<string, PendingSignedResourceContext>;
  private readonly ttpInvitationEndpoint: string;
  private ttpConnectionId?: string;
  private ttpConnectionPromise?: Promise<ConnectionRecord>;

  public constructor(args: AgentInitializerArgs) {
    super();
    this.agent = new Agent({
      config: {
        label: 'SecureSolidApplication',
        walletConfig: {
          id: 'CommunitySolidServerSecure',
          key: 'solidserver000000000000000000010',
        },
        endpoints: [ 'http://solid-css:3015' ],
        autoUpdateStorageOnStartup: true,
        logger: new ConsoleLogger(LogLevel.debug),
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
    this.lastKeyForMsgEncryption = {};
    this.operationHandler = args.operationHandler;
    this.requestParser = args.requestParser;
    this.jwsGraphService = args.jwsGraphService;
    this.pendingSignedResourceContexts = new Map<string, PendingSignedResourceContext>();
    this.ttpInvitationEndpoint = args.ttpInvitationEndpoint ?? DEFAULT_TTP_INVITATION_ENDPOINT;
  }

  /**
     * A class that can be used to instantiate and start a server based on a Component.js configuration.
     */

  public async sendTheProof(options: ProofRequestOptions): Promise<void> {
    const listener = async ({ payload }: BaseEvent): Promise<void> => {
      /* If you want, I can generate also a more professional VPR, using the agent */
      const connRecord = (payload as ConnectionStateChangedEvent['payload']).connectionRecord;
      if (connRecord.state !== DidExchangeState.Completed || connRecord.outOfBandId !== options.outOfBandId) {
        return;
      }

      this.agent.events.off(ConnectionEventTypes.ConnectionStateChanged, listener);
      if (connRecord.id === this.ttpConnectionId) {
        this.logger.debug(`Ignoring proof request on reserved TTP connection ${ connRecord.id }.`);
        return;
      }

      try {
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
      } catch (error) {
        this.agent.events.off(ConnectionEventTypes.ConnectionStateChanged, listener);
        throw error;
      }
    };

    this.agent.events.on(ConnectionEventTypes.ConnectionStateChanged, listener);
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

    this.agent.events.on(BasicMessageEventTypes.BasicMessageStateChanged, async ({ payload }: BaseEvent) => {
      const { basicMessageRecord, message } = payload as BasicMessageStateChangedEvent['payload'];
      const connectionId: any = basicMessageRecord.connectionId;
      const msg: any = message!;
      const content = msg.content;
      const objWrappedVP = JSON.parse(content);
      if (objWrappedVP.type !== undefined && objWrappedVP.type[0] === 'VerifiablePresentation') {
        const requestUrl = this.extractRequestedResourceFromPresentation(objWrappedVP);
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
        // HERE WE NEED TO CHANGE, WE NEED TO CHECK THE CONDITIONS AND
        // ON THE BASIS OF THIS WE WILL RELEASE THE ENCRYPTED FILE OR NOT.
        // IF THE acl:Apply is a Read then goes with simple access to resource
        // and if the acl:Apply is a NonRepudiableRead then goes with the encrypted file, 
        // and the signature of the hash of the file.
        
        const response: HttpResponse = {} as any;
        const responseDescription = await this.operationHandler.handle({request, operation, response});
        const txtToCypher = await readableToString(responseDescription.data!);
        const theMessage = new BasicMessage({ content: txtToCypher });

        let startTime:Date = new Date();
        const { encryptedMessage, symKey } = await packDidCommMessageWithReturn(
            this.agent.context,
            theMessage,
            {
              recipientKeys: await this.getTtpRecipientKeys(),
              routingKeys: [],
              senderKey: null,
            },
        );
        let endTime:Date = new Date();
        const milliDiff: number = endTime.getTime()
            - startTime.getTime();

        // get seconds
        this.logger.info(`Time elapsed ${ milliDiff } `)

        const messageHash = sha256(JSON.stringify(theMessage));
        const requesterDid = this.extractRequesterDidFromPresentation(objWrappedVP);
        await this.attachNonRepudiationMaterial(encryptedMessage, requesterDid, messageHash);
        /* We also need the hash encrypted for the TTP so that it can check if the app applied the right signature */
        /*const responseEncryptHash = await packDidCommMessageWithReturn(
            this.agent.context,
            new BasicMessage({ content: messageHash }),
            {
              recipientKeys: await this.getTtpRecipientKeys(),
              routingKeys: [],
              senderKey: null,
            },
        );*/
        this.lastKeyForMsgEncryption[messageHash] = symKey;
        this.pendingSignedResourceContexts.set(messageHash, {
          connectionId,
          messageHash,
          requestedResource: requestUrl,
          requesterDid,
        });
        /*
         * FUTURE OPTIONAL APP -> TTP FLOW (disabled on purpose)
         *
         * After receiving `encryptedMessage` from the CSS, the app can optionally ask the TTP
         * for `keyForDecrypt` before contacting the CSS. The app should send two pieces of
         * evidence to `checkResource`:
         * 1. `encryptedResource`: the encrypted envelope received from the CSS
         * 2. `nrr`: the NRR VC (or legacy JWS) that the app will later send back to the CSS as
         *    `signedResource`
         *
         * Pseudo-flow in the app:
         *
         * const nrr = await appAgent.signCredential({
         *   credentialSubject: {
         *     id: requesterDid,
         *     signedHash: encryptedMessage.hash,
         *     requestedResource: requestUrl,
         *   },
         *   // legacy fallback could still produce the older JWS payload
         * });
         *
         * await fetch('http://demo-ttp:<ttp-api-port>/checkResource', {
         *   method: 'POST',
         *   headers: { 'content-type': 'application/json' },
         *   body: JSON.stringify({
         *     encryptedResource: encryptedMessage,
         *     nrr,
         *     requestedResource: requestUrl,
         *     requesterDid,
         *   }),
         * });
         *
         * The same `nrr` is then sent to the CSS as `signedResource`, while the TTP keeps
         * an auditable copy of the NRR plus the optional encrypted resource envelope.
         */
        this.logger.info(`Sending encrypted message to the App, hash ${ messageHash } ...`);
        await this.agent.basicMessages.sendMessage(connectionId, JSON.stringify(/*{encryptedMessage: */encryptedMessage /*,responseEncryptHash: responseEncryptHash*/));

      } else if (objWrappedVP.signedResource !== undefined) {
        const verificationResult = await this.verifySignedResource(objWrappedVP.signedResource);
        this.logger.info(`Signed resource (${ verificationResult.signedResourceType }) validated, sending symmetric key to the App ...`);
        const keyForDecrypt = this.lastKeyForMsgEncryption[verificationResult.messageHash];
        const pendingContext = this.pendingSignedResourceContexts.get(verificationResult.messageHash);

        if (keyForDecrypt === undefined) {
          throw new Error(`No decryption key found for signed hash ${ verificationResult.messageHash }.`);
        }
        if (pendingContext === undefined) {
          throw new Error(`No pending signed resource context found for signed hash ${ verificationResult.messageHash }.`);
        }
        if (verificationResult.messageHash !== pendingContext.messageHash) {
          throw new Error('The signed resource hash does not match the expected message hash.');
        }
        if (verificationResult.requesterDid !== undefined && verificationResult.requesterDid !== pendingContext.requesterDid) {
          throw new Error('The signed resource requester DID does not match the pending request context.');
        }
        if (verificationResult.requestedResource !== undefined &&
            verificationResult.requestedResource !== pendingContext.requestedResource) {
          throw new Error('The signed resource requested resource does not match the pending request context.');
        }

        /*
         * FUTURE OPTIONAL CSS -> TTP DISPUTE FLOW (disabled on purpose)
         *
         * Today the CSS verifies the app NRR locally and releases `keyForDecrypt`.
         * In a dispute scenario, before releasing the key, the CSS could forward the
         * app NRR to the TTP so that the TTP can validate that the NRR is genuinely
         * signed by the app DID and matches the evidence previously stored via
         * `checkResource`.
         *
         * await fetch('http://demo-ttp:<ttp-api-port>/disputeFromCSS', {
         *   method: 'POST',
         *   headers: { 'content-type': 'application/json' },
         *   body: JSON.stringify({
         *     nrr: verificationResult.signedResource,
         *     messageHash: verificationResult.messageHash,
         *     requestedResource: pendingContext.requestedResource,
         *     requesterDid: pendingContext.requesterDid,
         *     // optional: encryptedResource if the CSS wants to re-submit the envelope
         *   }),
         * });
         *
         * Expected TTP-side checks:
         * - verify that `nrr` is a genuine VC/JWS from the app DID
         * - compare the NRR payload against the stored encrypted resource / hash evidence
         * - return an auditable dispute result to the CSS
         */
        await this.jwsGraphService.storeVerifiedJws({
          connectionId: pendingContext.connectionId,
          messageHash: verificationResult.messageHash,
          requestedResource: pendingContext.requestedResource,
          requesterDid: pendingContext.requesterDid,
          signedResource: verificationResult.signedResource,
          signedResourceType: verificationResult.signedResourceType,
          signerId: verificationResult.signerId,
          verifiedAt: new Date().toISOString(),
        });

        await this.agent.basicMessages.sendMessage(connectionId, JSON.stringify({ keyForDecrypt }));
        delete this.lastKeyForMsgEncryption[verificationResult.messageHash];
        this.pendingSignedResourceContexts.delete(verificationResult.messageHash);
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
    }
  }

  public async getTtpRecipientKeys(): Promise<Key[]> {
    const connectionRecord = await this.ensureTtpConnection();
    if (!connectionRecord.theirDid) {
      throw new Error(`TTP connection ${ connectionRecord.id } has no peer DID.`);
    }

    const didDocument = await this.agent.dids.resolveDidDocument(connectionRecord.theirDid);
    if (didDocument.recipientKeys.length === 0) {
      throw new Error(`TTP DID ${ connectionRecord.theirDid } exposes no DIDComm recipient keys.`);
    }

    return didDocument.recipientKeys;
  }

  private async ensureTtpConnection(): Promise<ConnectionRecord> {
    if (this.ttpConnectionId) {
      try {
        const existingConnection = await this.agent.connections.getById(this.ttpConnectionId);
        return existingConnection.isReady
          ? existingConnection
          : await this.agent.connections.returnWhenIsConnected(existingConnection.id, {
            timeoutMs: DEFAULT_TTP_CONNECTION_TIMEOUT_MS,
          });
      } catch {
        this.ttpConnectionId = undefined;
      }
    }

    if (!this.ttpConnectionPromise) {
      this.ttpConnectionPromise = this.initializeTtpConnection()
        .catch((error: unknown) => {
          this.ttpConnectionPromise = undefined;
          throw error;
        });
    }

    return this.ttpConnectionPromise;
  }

  private async initializeTtpConnection(): Promise<ConnectionRecord> {
    this.logger.info(`Opening reserved DIDComm channel with TTP via ${ this.ttpInvitationEndpoint } ...`);
    const invitationUrl = await this.fetchTtpInvitationUrl();
    const { connectionRecord } = await this.agent.oob.receiveInvitationFromUrl(invitationUrl, {
      autoAcceptConnection: true,
    });

    if (!connectionRecord) {
      throw new Error('TTP invitation did not create a connection record.');
    }

    const readyConnection = connectionRecord.isReady
      ? connectionRecord
      : await this.agent.connections.returnWhenIsConnected(connectionRecord.id, {
        timeoutMs: DEFAULT_TTP_CONNECTION_TIMEOUT_MS,
      });

    this.ttpConnectionId = readyConnection.id;
    this.logger.info(`Reserved TTP channel ready on connection ${ readyConnection.id }.`);
    return readyConnection;
  }

  private async fetchTtpInvitationUrl(): Promise<string> {
    const invitationResponse = await fetch(this.ttpInvitationEndpoint);
    if (!invitationResponse.ok) {
      throw new Error(`TTP invitation endpoint responded with ${ invitationResponse.status } ${ invitationResponse.statusText }.`);
    }

    const body = await invitationResponse.json() as Record<string, unknown>;
    const invitationUrl = typeof body.url === 'string'
      ? body.url
      : typeof body.invitationUrl === 'string'
        ? body.invitationUrl
        : undefined;

    if (!invitationUrl) {
      throw new Error('TTP invitation endpoint did not return a valid invitation URL.');
    }

    return invitationUrl;
  }


  private async createSuite(did:string): Promise<any> {
    let created_dids = await this.agent.dids.getCreatedDids({method: 'web'});
    const signingKey = created_dids[0].didDocument!.authentication![0] as string
    const signatureSuiteRegistry =  this.agent.dependencyManager.resolve(SignatureSuiteRegistry);
    const suiteInfo = signatureSuiteRegistry.getByProofType("Ed25519Signature2018");
    const WalletKeyPair = createWalletKeyPairClass(this.agent.context.wallet)

    const sigKey = await getKeyFromVerificationMethod(created_dids[0].didDocument!.verificationMethod![0]);
    const keyPair = new WalletKeyPair({
      controller: did,
      id: signingKey,
      key: sigKey,
      wallet: this.agent.context.wallet
    });

    const SuiteClass = suiteInfo.suiteClass;
    const toReturn = new SuiteClass({
      key: keyPair,
      LDKeyClass: WalletKeyPair,
      proof: {
        verificationMethod: signingKey
      },
      useNativeCanonize: false
    });
    this.logger.info(toReturn);
    return toReturn;
  }

  private async generateHashCredentials(holderDID:string, hash:string):Promise<unknown> {
    let created_dids = await this.agent.dids.getCreatedDids({method: 'web'});
    let did = created_dids[0].didDocument!.id;
    let suite =  await this.createSuite(did);
    const credential = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://secureapp.solidcommunity.net/public/NonRepudiationContext.jsonld"
      ],
      "id": "https://example.com/credentials/1872",
      "type": ["VerifiableCredential", "NonRepudiableOrigin"],
      "issuer": did,
      "issuanceDate": new Date().toISOString().replace(/\d{2}\.\d{3,}(?=Z$)/, num =>
          Number(num).toFixed(2).padStart(5, "0")),
      "credentialSubject": {
        "id": holderDID
      },
      "signedHash": hash
    };

    return await vc.issue({
      credential: credential,
      suite: suite,
      documentLoader: defaultDocumentLoader(this.agent.context)
    });

  }

  private async attachNonRepudiationMaterial(
    encryptedMessage: MutableEncryptedMessage,
    requesterDid: string,
    messageHash: string,
  ): Promise<void> {
    encryptedMessage.hash = messageHash;
    encryptedMessage.hashCredential = await this.generateHashCredentials(requesterDid, messageHash);

    const jwsService = new JwsService();
    const created_dids = await this.agent.dids.getCreatedDids({method: 'web'});
    const currentDid = created_dids[0];
    const verkey = currentDid.didDocument!.verificationMethod?.[0].publicKeyBase58;
    if (typeof verkey === 'string') {
      const key = Key.fromPublicKeyBase58(verkey, KeyType.Ed25519);
      const kid = new DidKey(key).did;

      // The app sends this signed payload back to request the symmetric key,
      // so the JWS payload must remain the raw message hash.
      const payload = TypedArrayEncoder.fromString(messageHash);
      encryptedMessage.signatureFromCSS = await jwsService.createJws(this.agent.context, {
        payload,
        key,
        header: {
          kid,
        },
        protectedHeaderOptions: {
          alg: JwaSignatureAlgorithm.EdDSA,
          jwk: getJwkFromKey(key),
        }
      });
    }
  }

  private async verifySignedResource(signedResource: unknown): Promise<VerifiedSignedResourceResult> {
    const normalizedSignedResource = this.normalizeSignedResource(signedResource);
    if (this.isVerifiableCredentialSignedResource(normalizedSignedResource)) {
      return this.verifySignedResourceCredential(normalizedSignedResource);
    }

    return this.verifyLegacySignedResourceJws(normalizedSignedResource);
  }

  private async verifySignedResourceCredential(
    signedResource: Record<string, unknown>,
  ): Promise<VerifiedSignedResourceResult> {
    const credential = W3cJsonLdVerifiableCredential.fromJson(signedResource);
    const verificationResult = await this.agent.w3cCredentials.verifyCredential({ credential });
    if (!verificationResult.isValid) {
      throw new Error(`The signedResource VC is not valid.${ verificationResult.error ? ` Error = ${ verificationResult.error.message }` : '' }`);
    }

    return {
      messageHash: this.extractSignedHashFromCredential(credential),
      requestedResource: this.extractRequestedResourceFromCredential(credential),
      requesterDid: this.extractRequesterDidFromCredential(credential),
      signedResource,
      signedResourceType: 'vc',
      signerId: this.extractSignerIdFromCredential(credential),
    };
  }

  private async verifyLegacySignedResourceJws(
    signedResource: Record<string, unknown>,
  ): Promise<VerifiedSignedResourceResult> {
    const jwsService = new JwsService();
    const legacyJws = this.toLegacySignedResourceJws(signedResource);

    const { isValid } = await jwsService.verifyJws(this.agent.context, {
      jws: legacyJws,
      jwkResolver: ({ jws: { header } }) => {
        if (typeof header.kid !== 'string' || !isDid(header.kid, 'key')) {
          throw new Error('JWS header kid must be a did:key DID.');
        }
        const didKey = DidKey.fromDid(header.kid);
        return getJwkFromKey(didKey.key);
      },
    });

    if (!isValid) {
      throw new Error('The signedResource JWS is not valid.');
    }

    const decodedSignedPayload = TypedArrayEncoder.toUtf8String(
      TypedArrayEncoder.fromBase64(legacyJws.payload),
    );

    return {
      messageHash: this.extractSignedHashFromSignedPayload(decodedSignedPayload),
      signedResource,
      signedResourceType: 'jws',
      signerId: this.extractSignerIdFromLegacyJws(signedResource),
    };
  }

  private normalizeSignedResource(signedResource: unknown): Record<string, unknown> {
    if (typeof signedResource === 'string') {
      try {
        const parsedSignedResource = JSON.parse(signedResource);
        if (parsedSignedResource && typeof parsedSignedResource === 'object') {
          return parsedSignedResource as Record<string, unknown>;
        }
      } catch {
        throw new Error('Could not parse signedResource as JSON.');
      }
    }

    if (signedResource && typeof signedResource === 'object') {
      return signedResource as Record<string, unknown>;
    }

    throw new Error('signedResource must be a JSON object.');
  }

  private toLegacySignedResourceJws(signedResource: Record<string, unknown>): {
    header: Record<string, unknown>;
    protected: string;
    signature: string;
    payload: string;
  } {
    const header = signedResource.header;
    const protectedHeader = signedResource.protected;
    const signature = signedResource.signature;
    const payload = signedResource.payload;

    if (!header || typeof header !== 'object' || Array.isArray(header)) {
      throw new Error('The signedResource JWS header must be an object.');
    }
    const headerRecord = header as Record<string, unknown>;
    if (typeof protectedHeader !== 'string') {
      throw new Error('The signedResource JWS protected header must be a base64url string.');
    }
    if (typeof signature !== 'string') {
      throw new Error('The signedResource JWS signature must be a base64url string.');
    }
    if (typeof payload !== 'string') {
      throw new Error('The signedResource JWS payload must be a base64url string.');
    }

    return {
      header: headerRecord,
      protected: protectedHeader,
      signature,
      payload,
    };
  }

  private isVerifiableCredentialSignedResource(signedResource: Record<string, unknown>): boolean {
    const type = signedResource.type;
    if (typeof type === 'string') {
      return type === 'VerifiableCredential';
    }

    return Array.isArray(type) && type.includes('VerifiableCredential');
  }

  private extractSignedHashFromCredential(credential: W3cJsonLdVerifiableCredential): string {
    const signedHash = this.extractCredentialSubjectValue(credential, 'signedHash');
    if (typeof signedHash === 'string') {
      return signedHash;
    }

    throw new Error('Could not extract credentialSubject.signedHash from the signedResource VC.');
  }

  private extractRequestedResourceFromCredential(credential: W3cJsonLdVerifiableCredential): string | undefined {
    const requestedResource = this.extractCredentialSubjectValue(credential, 'requestedResource');
    return typeof requestedResource === 'string' ? requestedResource : undefined;
  }

  private extractRequesterDidFromCredential(credential: W3cJsonLdVerifiableCredential): string | undefined {
    const credentialSubject = Array.isArray(credential.credentialSubject)
      ? credential.credentialSubject[0]
      : credential.credentialSubject;

    return typeof credentialSubject?.id === 'string' ? credentialSubject.id : undefined;
  }

  private extractSignerIdFromCredential(credential: W3cJsonLdVerifiableCredential): string | undefined {
    const proof = Array.isArray(credential.proof) ? credential.proof[0] : credential.proof;
    if (typeof proof?.verificationMethod === 'string') {
      return proof.verificationMethod;
    }

    return undefined;
  }

  private extractCredentialSubjectClaims(credential: W3cJsonLdVerifiableCredential): Record<string, unknown> {
    const credentialSubject = Array.isArray(credential.credentialSubject)
      ? credential.credentialSubject[0]
      : credential.credentialSubject;

    if (credentialSubject && typeof credentialSubject === 'object') {
      const claims = (credentialSubject as { claims?: Record<string, unknown> }).claims;
      if (claims && typeof claims === 'object') {
        return claims;
      }
    }

    return {};
  }

  private extractCredentialSubjectValue(
    credential: W3cJsonLdVerifiableCredential,
    key: string,
  ): unknown {
    const credentialSubject = Array.isArray(credential.credentialSubject)
      ? credential.credentialSubject[0]
      : credential.credentialSubject;

    if (credentialSubject && typeof credentialSubject === 'object') {
      const directValue = (credentialSubject as Record<string, unknown>)[key];
      if (directValue !== undefined) {
        return directValue;
      }
    }

    return this.extractCredentialSubjectClaims(credential)[key];
  }

  private extractSignerIdFromLegacyJws(jws: Record<string, unknown>): string | undefined {
    const header = typeof jws.header === 'object' && jws.header ? jws.header as Record<string, unknown> : undefined;
    return typeof header?.kid === 'string' ? header.kid : undefined;
  }

  private extractSignedHashFromSignedPayload(signedPayload: string): string {
    if (/^[a-f0-9]{64}$/iu.test(signedPayload)) {
      return signedPayload;
    }

    let parsedPayload: any;
    try {
      parsedPayload = JSON.parse(signedPayload);
    } catch {
      throw new Error('Could not parse signedResource payload.');
    }

    if (typeof parsedPayload === 'string' && /^[a-f0-9]{64}$/iu.test(parsedPayload)) {
      return parsedPayload;
    }

    if (parsedPayload && typeof parsedPayload === 'object') {
      if (typeof parsedPayload.hash === 'string') {
        if (typeof parsedPayload.signatureFromCSS?.payload === 'string') {
          const cssSignedHash = TypedArrayEncoder.toUtf8String(
            TypedArrayEncoder.fromBase64(parsedPayload.signatureFromCSS.payload),
          );

          if (cssSignedHash !== parsedPayload.hash) {
            throw new Error('The signed resource hash does not match the CSS signature payload.');
          }
        }

        const credentialHash = this.extractSignedHashFromHashCredential(parsedPayload.hashCredential);
        if (credentialHash !== undefined && credentialHash !== parsedPayload.hash) {
          throw new Error('The signed resource hash does not match the non-repudiation credential.');
        }

        return parsedPayload.hash;
      }

      const credentialHash = this.extractSignedHashFromHashCredential(parsedPayload.hashCredential);
      if (credentialHash !== undefined) {
        return credentialHash;
      }

      if (typeof parsedPayload.signatureFromCSS?.payload === 'string') {
        return TypedArrayEncoder.toUtf8String(
          TypedArrayEncoder.fromBase64(parsedPayload.signatureFromCSS.payload),
        );
      }
    }

    throw new Error('Could not extract a hash from signedResource payload.');
  }

  private extractSignedHashFromHashCredential(hashCredential: unknown): string | undefined {
    if (hashCredential === undefined || hashCredential === null) {
      return undefined;
    }

    let parsedCredential = hashCredential;
    if (typeof parsedCredential === 'string') {
      try {
        parsedCredential = JSON.parse(parsedCredential);
      } catch {
        return undefined;
      }
    }

    if (parsedCredential && typeof parsedCredential === 'object') {
      const credentialRecord = parsedCredential as Record<string, unknown>;
      if (typeof credentialRecord.signedHash === 'string') {
        return credentialRecord.signedHash;
      }

      const credentialSubject = Array.isArray(credentialRecord.credentialSubject)
        ? credentialRecord.credentialSubject[0]
        : credentialRecord.credentialSubject;
      if (credentialSubject && typeof credentialSubject === 'object') {
        const subjectRecord = credentialSubject as Record<string, unknown>;
        if (typeof subjectRecord.signedHash === 'string') {
          return subjectRecord.signedHash;
        }
        if (subjectRecord.claims && typeof subjectRecord.claims === 'object') {
          const claimSignedHash = (subjectRecord.claims as Record<string, unknown>).signedHash;
          if (typeof claimSignedHash === 'string') {
            return claimSignedHash;
          }
        }
      }
    }

    return undefined;
  }

  private extractRequestedResourceFromPresentation(wrappedPresentation: any): string {
    const presentation = wrappedPresentation?.wrappedVP ?? wrappedPresentation;
    const requestedResource = presentation?.requestACP?.target;
    if (typeof requestedResource === 'string') {
      return requestedResource;
    }

    throw new Error('Could not extract the requested resource from the presentation.');
  }

  private extractRequesterDidFromPresentation(wrappedPresentation: any): string {
    const presentation = wrappedPresentation?.wrappedVP ?? wrappedPresentation;
    if (typeof presentation?.holder === 'string') {
      return presentation.holder;
    }

    const firstCredential = Array.isArray(presentation?.verifiableCredential) ? presentation.verifiableCredential[0] : undefined;
    const credentialSubject = firstCredential?.credentialSubject;
    if (typeof credentialSubject?.id === 'string') {
      return credentialSubject.id;
    }
    if (Array.isArray(credentialSubject)) {
      const subjectWithId = credentialSubject.find((subject: any): boolean => typeof subject?.id === 'string');
      if (typeof subjectWithId?.id === 'string') {
        return subjectWithId.id;
      }
    }

    throw new Error('Could not extract the requester DID from the presentation.');
  }

}
