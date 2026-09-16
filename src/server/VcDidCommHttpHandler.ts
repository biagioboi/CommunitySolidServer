import type { V2RequestPresentationMessage } from '@credo-ts/core';
import {
  BasicMessage, ConnectionEventTypes, ConnectionRecord,
  DidExchangeState, DidKey, getJwkFromKey, isDid, JwsService,
} from '@credo-ts/core';
import { sha256 } from 'js-sha256';
import type { RequestParser } from '../http/input/RequestParser';
import type { ErrorHandler } from '../http/output/error/ErrorHandler';
import { ResponseDescription } from '../http/output/response/ResponseDescription';
import type { ResponseWriter } from '../http/output/ResponseWriter';
import { BasicRepresentation } from '../http/representation/BasicRepresentation';
import { RepresentationMetadata } from '../http/representation/RepresentationMetadata';
import { AgentInitializer } from '../init/AgentInitializer';
import { getLoggerFor } from '../logging/LogUtil';
import { packDidCommMessageWithReturn } from '../util/DidCommUtil';
import { assertError } from '../util/errors/ErrorUtil';
import { HttpError } from '../util/errors/HttpError';
import { readJsonStream, readableToString } from '../util/StreamUtil';
import { toLiteral } from '../util/TermUtil';
import { HTTP, SOLID_HTTP, XSD } from '../util/Vocabularies';
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
      console.log(result);
      return await this.responseWriter.handleSafe({ response, result });
    }
  }

  // This handler will only respond to requests that have:
  // -'vc' header (Initial Request)
  // -'vp' header (Secondary Request/Verifiable Presentation)
  public async canHandle({ request, response }: HttpHandlerInput): Promise<void> {
    // Follow-up legs of a challenge this handler itself issued: real validation (nonce/domain,
    // VP, signed receipt) happens downstream in handleRequest - canHandle only routes.
    if (request.headers.didvc !== undefined
      || request.headers.encryptedrequest !== undefined
      || this.isSecondaryRequest(request)
      || this.isReleaseRequest(request)) {
      return;
    }
    if (request.method === 'OPTIONS') {
      throw new Error('Required headers missing: \'didvc\' or \'encryptedrequest\'.');
    }
    const operation = await this.requestParser.handleSafe(request);
    if (await this.operationHandler.requiresNonRepudiableRead(operation)) {
      return;
    }
    throw new Error('Required headers missing: \'didvc\' or \'encryptedrequest\'.');
  }

  /**
     * Interprets the request and generates a response description that can be used by the ResponseWriter to respond
     */
  public async handleRequest(request: HttpRequest, response: HttpResponse, body?: NodeJS.Dict<any>):
  Promise<ResponseDescription> {
    // Handle if it is the initial request
    // I added this if here just to move the compuatation to my point non repudiation
    this.logger.info('Checking if it is the initial request...');
    this.logger.info(`Request headers: ${JSON.stringify(request.headers)}`);

    // Handle the non-repudiable release follow-up: the App sends back its signed NRR to
    // obtain the decryption key for a previously received `encryptedresource`.
    if (this.isReleaseRequest(request)) {
      this.logger.info('Detected Release Request');
      return await this.handleReleaseRequest(request);
    }

    // Handle plain requests targeting a resource that only grants public read through
    // the non-repudiable read mode (acl:NRRead) - challenge with the DID flow directly.
    if (request.headers.didvc === undefined && !this.isSecondaryRequest(request)) {
      const operation = await this.requestParser.handleSafe(request);
      if (await this.operationHandler.requiresNonRepudiableRead(operation)) {
        this.logger.info('Detected request to a NonRepudiableRead-gated resource');
        return await this.handlePassiveChallenge(request);
      }
    }

    if ((request.headers.didvc !== undefined) && this.isInitialRequest(request.headers)) {
      this.logger.info('Detected Initial Request');
      if (await this.validUserAppIssuer(request, request.headers)) {
        return await this.handleInitialRequest(request, request.headers);
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
  public isInitialRequest(header: NodeJS.Dict<any>): boolean {
    return header.issuer !== undefined &&
            header.client !== undefined &&
            header.agent !== undefined;
  }

  public isRequestingVPCompliant(body: NodeJS.Dict<any>): boolean {
    return body.VPCompliant !== undefined;
  }

  // The secondary request will contain a VP in the header
  public isSecondaryRequest(request: HttpRequest): boolean {
    return request.headers.vp !== undefined;
  }

  // A release request carries the App's signed NRR, asking for the decryption key of a
  // previously received `encryptedresource`.
  public isReleaseRequest(request: HttpRequest): boolean {
    return request.headers.signedresource !== undefined;
  }

  // Builds the resource URL as actually reached by the client, using the real Host header
  // instead of a hardcoded origin - must match what the client itself uses as `target`.
  // Mirrors OriginalUrlExtractor's own host/protocol resolution (Forwarded/X-Forwarded-* takes
  // priority over the raw Host header), so the target this handler embeds in the challenge and
  // stores in nonceDomainMap always matches the resource identifier CSS itself will compute.
  private buildTargetUrl(request: HttpRequest): string {
    const single = (value: string | string[] | undefined): string | undefined =>
      Array.isArray(value) ? value[0] : value;

    const protocol = single(request.headers['x-forwarded-proto']) ?? (request.connection && (request.connection as any).encrypted ? 'https' : 'http');
    const host = single(request.headers['x-forwarded-host']) ?? single(request.headers.host) ?? 'localhost:3000';
    return `${protocol}://${host}${request.url}`;
  }

  // Deal with the initial request and respond with a VP Request. The proof request is fully
  // embedded in the WWW-Authenticate header (connectionless) - no DIDComm connection/OOB
  // invitation is established for this leg; the VP comes back via the `vp` HTTP header instead.
  public async handleInitialRequest(request: HttpRequest, body: NodeJS.Dict<any>): Promise<ResponseDescription> {
    const crypto = require('crypto');
    const nonce = crypto.randomBytes(16).toString('base64');
    this.logger.info(`Generated Nonce: ${nonce}`);
    const target = this.buildTargetUrl(request);
    // Store nonce and domain in the map
    this.nonceDomainMap.set(nonce, target);

    const proofRequestOptions = {
      acp: {
        target,
        issuer: body.issuer,
        client: body.client,
        agent: body.agent,
      },
      challenge: nonce,
    };

    const metadata = new RepresentationMetadata();
    metadata.add(HTTP.terms.statusCodeNumber, toLiteral(401, XSD.terms.integer));
    metadata.add(
      SOLID_HTTP.terms.wwwAuthenticate,
      await this.agentInitializer.createDidCommAuthenticateHeader(proofRequestOptions),
    );

    return new ResponseDescription(401, metadata);
  }

  // Deal with a plain request to a resource that only grants public read through the
  // non-repudiable read mode (acl:NRRead). Unlike handleInitialRequest, no issuer/client/agent
  // is known yet - identity is only revealed and verified once the VP is presented.
  public async handlePassiveChallenge(request: HttpRequest): Promise<ResponseDescription> {
    const crypto = require('crypto');
    const nonce = crypto.randomBytes(16).toString('base64');
    this.logger.info(`Generated Nonce: ${nonce}`);
    const target = this.buildTargetUrl(request);
    this.nonceDomainMap.set(nonce, target);

    const proofRequestOptions = {
      acp: {
        target,
      },
      challenge: nonce,
    };

    const metadata = new RepresentationMetadata();
    metadata.add(HTTP.terms.statusCodeNumber, toLiteral(401, XSD.terms.integer));
    metadata.add(
      SOLID_HTTP.terms.wwwAuthenticate,
      await this.agentInitializer.createDidCommAuthenticateHeader(proofRequestOptions),
    );

    return new ResponseDescription(401, metadata);
  }

  // Handles the follow-up leg of the non-repudiable release: the App sends back its signed NRR
  // (as the `signedresource` header) and receives the `keyfordecrypt` header in response.
  public async handleReleaseRequest(request: HttpRequest): Promise<ResponseDescription> {
    const signedResource = JSON.parse(request.headers.signedresource as string);
    const { keyForDecrypt } = await this.agentInitializer.releaseKeyForSignedResource(signedResource);

    const metadata = new RepresentationMetadata();
    metadata.add(HTTP.terms.statusCodeNumber, toLiteral(200, XSD.terms.integer));
    metadata.add(SOLID_HTTP.terms.keyForDecrypt, JSON.stringify(keyForDecrypt));
    return new ResponseDescription(200, metadata);
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
      const theMessage = new BasicMessage({ content: stringToEncrypt });
      const { encryptedMessage, symKey } = await packDidCommMessageWithReturn(
          this.agentInitializer.agent.context,
          theMessage,
          {
            recipientKeys: await this.agentInitializer.getTtpRecipientKeys(),
            routingKeys: [],
            senderKey: null,
          },
      );

      // Hash the raw content directly - see the same fix and rationale in
      // AgentInitializer.buildNonRepudiableRelease.
      const messageHash = sha256(stringToEncrypt);
      encryptedMessage.hash = messageHash;
      /*
       * The same future app -> TTP `checkResource` flow documented in AgentInitializer.ts
       * also applies here: the app could optionally forward this `encryptedMessage` plus
       * the NRR it will send back to the CSS, so the TTP can store both before releasing
       * `keyForDecrypt`.
       */
      this.agentInitializer.lastKeyForMsgEncryption[messageHash] = symKey;
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
