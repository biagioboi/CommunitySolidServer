import type { V2RequestPresentationMessage } from '@credo-ts/core';
import {
  BasicMessage, ConnectionEventTypes, ConnectionRecord,
  ConsoleLogger, DidExchangeState, DidKey, getJwkFromKey, isDid, JwsService,
} from '@credo-ts/core';
import { EnvelopeService } from '@credo-ts/core/build/agent/EnvelopeService';
import { sha256 } from 'js-sha256';
import type { RequestParser } from '../http/input/RequestParser';
import type { ErrorHandler } from '../http/output/error/ErrorHandler';
import { ResponseDescription } from '../http/output/response/ResponseDescription';
import type { ResponseWriter } from '../http/output/ResponseWriter';
import { BasicRepresentation } from '../http/representation/BasicRepresentation';
import { AgentInitializer } from '../init/AgentInitializer';
import { getLoggerFor } from '../logging/LogUtil';
import { assertError } from '../util/errors/ErrorUtil';
import { HttpError } from '../util/errors/HttpError';
import { readJsonStream, readableToString } from '../util/StreamUtil';
import type { HttpHandlerInput } from './HttpHandler';
import { HttpHandler } from './HttpHandler';
import type { HttpRequest } from './HttpRequest';
import type { HttpResponse } from './HttpResponse';
import type { VcAuthorizingHttpHandler } from './VcAuthorizingHttpHandler';

export interface VcDidCommHttpHandlerArgs {
  /**
     * Parses the incoming requests.
     */
  requestParser: RequestParser;
  /**
     * Converts errors to a serializable format.
     */
  errorHandler: ErrorHandler;
  /**
     * Writes out the response of the operation.
     */
  responseWriter: ResponseWriter;
  /**
     * Handler to send the operation to.
     */
  operationHandler: VcAuthorizingHttpHandler;

  agentInitializer: AgentInitializer;
}

/**
 * Initial message:
 * 1) Request is received for a resource:
 *  -It has 'VC' in its header - indicating this will be vc based protocol
 *  -Body contains user and vc issuer
 * 2) Check acp policy for matching user and vc issuer, using call to checkAcr method on VcAuthorizingHttpHandler
 *  -Generate nonce and domain, and save them in map
 *  -Generate VP request, include nonce and domain and respond with it in a 401 message
 *
 * Second message:
 * 1) Request is received with 'VP' in its header - indicates verifiable presentation
 *  -Check nonce and domain are valid compared with saved values
 *  -Pass data to VcAuthorizingHttpHandler to try to authorize
 *    -VpChecker should be called from there to verify VP and extract issuer and user credentials from it
 *    -Perform steps for it to be authorized
 *  -Return response
 */
export class VcDidCommHttpHandler extends HttpHandler {
  private readonly logger = getLoggerFor(this);

  private readonly requestParser: RequestParser;
  private readonly errorHandler: ErrorHandler;
  private readonly responseWriter: ResponseWriter;

  private readonly operationHandler: VcAuthorizingHttpHandler;
  private readonly nonceDomainMap: Map<any, any>;
  private readonly agentInitializer: AgentInitializer;

  public constructor(args: VcDidCommHttpHandlerArgs) {
    super();
    this.requestParser = args.requestParser;
    this.errorHandler = args.errorHandler;
    this.responseWriter = args.responseWriter;
    this.operationHandler = args.operationHandler;
    this.nonceDomainMap = new Map<any, any>();
    this.agentInitializer = args.agentInitializer;
  }

  public async handle({ request, response }: HttpHandlerInput): Promise<void> {
    let result: ResponseDescription;

    let body: NodeJS.Dict<any> = {};
    // Extract body from http request
    const operation = await this.requestParser.handleSafe(request);
    try {
      if (operation.body.data !== undefined) {
        body = await readJsonStream(operation.body.data);
      }
    } catch (error: unknown) {
      body = {};
      result = await this.handleError(error, request);
    }

    try {
      result = await this.handleRequest(request, response, body);
    } catch (error: unknown) {
      result = await this.handleError(error, request);
    }

    if (result) {
      this.logger.info('Sending Response...');
      return await this.responseWriter.handleSafe({ response, result });
    }
  }

  // This handler will only respond to requests that have:
  // -'vc' header (Initial Request)
  // -'vp' header (Secondary Request/Verifiable Presentation)
  public async canHandle({ request, response }: HttpHandlerInput): Promise<void> {
    if ((request.headers.didvc === undefined) && (request.headers.encryptedrequest === undefined)) {
      throw new Error('Required headers missing: \'didvc\' or \'encryptedrequest\'.');
    }
    if (request.method === "OPTION") {
      throw new Error('Required headers missing: \'didvc\' or \'encryptedrequest\'.');
    }
  }

  /**
     * Interprets the request and generates a response description that can be used by the ResponseWriter to respond
     */
  public async handleRequest(request: HttpRequest, response: HttpResponse, body?: NodeJS.Dict<any>):
  Promise<ResponseDescription> {
    // Handle if it is the initial request
    // I added this if here just to move the compuatation to my point non repudiation
    if ((request.headers.didvc !== undefined) && body && this.isInitialRequest(body)) {
      this.logger.info('Detected Initial Request');
      if (await this.validUserAppIssuer(request, body)) {
        return await this.handleInitialRequest(request, body);
      }
      throw new Error('Invalid user - app - issuer combination.');

      // Handle if it is the secondary request - proceed with authorization checks to verify VP
    } else if (this.isSecondaryRequest(request)) {
      this.logger.info('Detected Secondary Request');
      if (await this.validNonceAndDomain(request)) {
        try {
          return await this.handleSecondRequest(request, response);
        } catch (error) {
          throw error;
        }
      } else {
        this.logger.info('Invalid Nonce and Domain');
        throw new Error('Invalid Nonce and Domain.');
      }
    } else {
      throw new Error('Request not recognised');
    }
  }

  /**
     * Handles the error output correctly based on the preferences.
     */
  protected async handleError(error: unknown, request: HttpRequest): Promise<ResponseDescription> {
    assertError(error);
    const result = await this.errorHandler.handleSafe({ error, request });
    if (HttpError.isInstance(error) && result.metadata) {
      const quads = error.generateMetadata(result.metadata.identifier);
      result.metadata.addQuads(quads);
    }
    return result;
  }

  // Checks ACP policy to see if user, app, issuer combination match requested resource's access rules
  public async validUserAppIssuer(request: HttpRequest, body: NodeJS.Dict<any>): Promise<boolean> {
    const operation = await this.requestParser.handleSafe(request);
    const isValid: boolean = await this.operationHandler.checkAcr(operation, body);
    if (isValid) {
      this.logger.info('Valid User/App/Issuer combination');
    } else {
      this.logger.info('Invalid User/App/Issuer combination');
    }
    return isValid;
  }

  // Initial request body will indicate vc issuer, app, user
  public isInitialRequest(body: NodeJS.Dict<any>): boolean {
    return body.issuer !== undefined &&
            body.client !== undefined &&
            body.agent !== undefined;
  }

  public isRequestingVPCompliant(body: NodeJS.Dict<any>): boolean {
    return body.VPCompliant !== undefined;
  }

  // The secondary request will contain a VP in the header
  public isSecondaryRequest(request: HttpRequest): boolean {
    return request.headers.vp !== undefined;
  }

  // Deal with the initial request and respond with a VP Request
  public async handleInitialRequest(request: HttpRequest, body: NodeJS.Dict<any>): Promise<ResponseDescription> {
    const crypto = require('crypto');
    const nonce = crypto.randomBytes(16).toString('base64');
    this.logger.info(`Generated Nonce: ${nonce}`);
    const uri = request.url;
    // Store nonce and domain in the map
    this.nonceDomainMap.set(nonce, `http://localhost:3000${uri}`);
    const result: ResponseDescription = new ResponseDescription(401);

    const outOfBandRecord = await this.agentInitializer.agent.oob.createInvitation({
      autoAcceptConnection: true,
      handshake: true,
      invitationDid: this.agentInitializer.did,
    });

    const invitationUrl = outOfBandRecord.outOfBandInvitation.toUrl({ domain: this.agentInitializer.agent.config.endpoints[0] });
    await this.agentInitializer.sendTheProof({
      acp: {
        target: `http://localhost:3000${uri}`,
        issuer: body.issuer,
        client: body.client,
        agent: body.agent,
      },
      challenge: nonce,
    });


    result.data = new BasicRepresentation(JSON.stringify({invitationUrl: invitationUrl}), 'application/json').data;
    return result;
  }

  public async handleSecondRequest(request: HttpRequest, response: HttpResponse): Promise<ResponseDescription> {
    const operation = await this.requestParser.handleSafe(request);
    try {
      const result = await this.operationHandler.handle({ operation, request, response });
      const { challenge } = await this.operationHandler.extractNonceAndDomainFromNew(request);
      this.nonceDomainMap.delete(challenge);
      return result;
    } catch (error: unknown) {
      throw error;
    }
  }

  public async handleThirdRequest(request: HttpRequest, response: HttpResponse): Promise<ResponseDescription> {
    const operation = await this.requestParser.handleSafe(request);
    try {
      return await this.operationHandler.handleSafe({ operation, request, response });
      // Const {challenge} = await this.operationHandler.extractNonceAndDomainFromNew(request);
      // this.nonceDomainMap.delete(challenge);
      // return result;
    } catch (error: unknown) {
      throw error;
    }
  }


  public async handleEncryptedResourceRequest(request: HttpRequest, response: HttpResponse): Promise<ResponseDescription> {
    const stringHeader = request.headers.encryptedrequest! as string;
    const stringCssEncryptedResource = request.headers.cssencryptedresource! as string;
    const jws = JSON.parse(stringHeader);
    const payload = btoa(JSON.parse(stringCssEncryptedResource));
    const jwsService = new JwsService();
    this.logger.info("test here")
    this.logger.info(payload)
    const { isValid, signerKeys } = await jwsService.verifyJws(this.agentInitializer.agent.context, {
      jws: {
        ...jws,
        payload,
      },
      jwkResolver: ({ jws: { header } }) => {
        if (typeof header.kid !== 'string' || !isDid(header.kid, 'key')) {
          throw new Error('JWS header kid must be a did:key DID.');
        }
        const didKey = DidKey.fromDid(header.kid);
        return getJwkFromKey(didKey.key);
      },
    });
    this.logger.info(JSON.stringify(isValid));
    this.logger.info(JSON.stringify(signerKeys));
    const resp = new ResponseDescription(200);
    resp.data = new BasicRepresentation(JSON.stringify(request.headers.encryptedrequest), 'application/json').data;
    return resp;
  }

  public async handleAuthenticatedRequest(request: HttpRequest, response: HttpResponse): Promise<ResponseDescription> {
    const resource = await this.handleThirdRequest(request, response);
    if (resource.data?.readable) {
      const stringToEncrypt = await readableToString(resource.data);
      const envService = new EnvelopeService(new ConsoleLogger());
      const theMessage = new BasicMessage({ content: stringToEncrypt });
      const responseEncrypt: any = await envService.packMessageWithReturn(
          this.agentInitializer.agent.context,
          theMessage,
          {
            recipientKeys: [ this.agentInitializer.ttpKey ],
            routingKeys: [],
            senderKey: null,
          },
      );

      const encryptedMessage = responseEncrypt.envelope;
      encryptedMessage.hash = sha256(JSON.stringify(theMessage));
      this.agentInitializer.lastKeyForMsgEncryption.push({hash: encryptedMessage.hash, symKey: responseEncrypt.sym_key});
      const resp = new ResponseDescription(200);
      resp.data = new BasicRepresentation(JSON.stringify(encryptedMessage), 'application/json').data;
      return resp;
    }
    return resource;
  }

  //
  // const z: any = JSON.parse(request.headers.vp as string ?? '{}');
  // const presentationParsed = JsonTransformer.fromJSON(z, W3cJsonLdVerifiablePresentation);
  //
  //     const response = await this.agentInitializer.agent.w3cCredentials.verifyPresentation({
  //       presentation: presentationParsed,
  //       challenge: objNew.challenge,
  //       domain: objNew.domain,
  //     });
  //

  public async validNonceAndDomain(request: HttpRequest): Promise<boolean> {
    this.logger.info('Checking Nonce and Domain...');
    try {
      const objNew = await this.operationHandler.extractNonceAndDomainFromNew(request);
      const nonce = objNew.challenge;
      const domain = objNew.domain;
      if (nonce !== undefined && this.nonceDomainMap.has(nonce)) {
        return domain === this.nonceDomainMap.get(nonce);
      }
      return false;
    } catch {
      return false;
    }
  }
}
