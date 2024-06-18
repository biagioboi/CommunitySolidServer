import {
  Agent,
  JsonTransformer,
  W3cJsonLdVerifiablePresentation,
  W3cWrappedVerifiablePresentation
} from '@credo-ts/core';
import type { Credentials } from '../authentication/Credentials';
import type { VcExtractor } from '../authentication/VcExtractor';
import type { VpChecker } from '../authentication/VpChecker';
import type { Authorizer } from '../authorization/Authorizer';
import type { PermissionReader } from '../authorization/PermissionReader';
import type { ModesExtractor } from '../authorization/permissions/ModesExtractor';
import type { Operation } from '../http/Operation';
import type { ResponseDescription } from '../http/output/response/ResponseDescription';
import { AgentInitializer } from '../init/AgentInitializer';
import { getLoggerFor } from '../logging/LogUtil';
import type { HttpRequest } from './HttpRequest';
import type { OperationHttpHandlerInput } from './OperationHttpHandler';
import { OperationHttpHandler } from './OperationHttpHandler';

export interface VcAuthorizingHttpHandlerArgs {
  /**
   * Extracts the Credentials from the body of the initial request of VC-based protocol.
   */
  credentialsExtractor: VcExtractor;

  /**
   * Verifies the Verifiable Presentation message and extracts valid Credentials from it.
   */
  vpChecker: VpChecker;

  /**
   * Extracts the required modes from the generated Operation.
   */
  modesExtractor: ModesExtractor;
  /**
   * Reads the permissions available for the Operation.
   */
  permissionReader: PermissionReader;
  /**
   * Verifies if the requested operation is allowed.
   */
  authorizer: Authorizer;
  /**
   * Handler to call if the operation is authorized.
   */
  operationHandler: OperationHttpHandler;
}

/**
 * Handles all the necessary steps for an authorization.
 * Errors if authorization fails, otherwise passes the parameter to the operationHandler handler.
 * The following steps are executed:
 *  - Extracting credentials from the request.
 *  - Extracting the required permissions.
 *  - Reading the allowed permissions for the credentials.
 *  - Validating if this operation is allowed.
 */
export class VcAuthorizingHttpHandler extends OperationHttpHandler {
  private readonly logger = getLoggerFor(this);

  private readonly credentialsExtractor: VcExtractor;
  private readonly vpChecker: VpChecker;
  private readonly modesExtractor: ModesExtractor;
  private readonly permissionReader: PermissionReader;
  private readonly authorizer: Authorizer;
  private readonly operationHandler: OperationHttpHandler;
  private readonly agentInitializer: AgentInitializer;

  public constructor(args: VcAuthorizingHttpHandlerArgs) {
    super();
    this.credentialsExtractor = args.credentialsExtractor;
    this.vpChecker = args.vpChecker;
    this.modesExtractor = args.modesExtractor;
    this.permissionReader = args.permissionReader;
    this.authorizer = args.authorizer;
    this.operationHandler = args.operationHandler;
    this.agentInitializer = new AgentInitializer();
    this.agentInitializer.agent.initialize().then().catch(e => this.logger.info('Errore'));
  }

  // Uses the VpChecker component to verify the VP, extracts credentials from a valid VP
  // Checks the extracted credentials against the acr file for the requested resource
  public async handle(input: OperationHttpHandlerInput): Promise<ResponseDescription> {
    const { request, operation } = input;
    let credentials: Credentials;
    try {
      credentials = await this.vpChecker.handle(request);
    } catch (error: unknown) {
      this.logger.info(`Authorization failed: ${(error as any).message}`);
      throw error;
    }
    this.logger.info(`Extracted credentials: ${JSON.stringify(credentials)}`);

    const requestedModes = await this.modesExtractor.handleSafe(operation);
    this.logger.info(`Retrieved required modes: ${
      [ ...requestedModes.entrySets() ].map(([ id, set ]): string => `{ ${id.path}: ${[ ...set ]} }`)
    }`);

    const availablePermissions = await this.permissionReader.handleSafe({ credentials, requestedModes });
    this.logger.info(`Available permissions are ${
      [ ...availablePermissions.entries() ].map(([ id, map ]): string => `{ ${id.path}: ${JSON.stringify(map)} }`)
    }`);

    try {
      await this.authorizer.handleSafe({ credentials, requestedModes, availablePermissions });
    } catch (error: unknown) {
      this.logger.info(`Authorization failed: ${(error as any).message}`);
      throw error;
    }
    this.logger.info(`Authorization succeeded, calling source handler`);
    return this.operationHandler.handleSafe(input);
  }

  // Check acr has appropriate combo for user, app, issuer
  // Uses VcExtractor and just takes these values from body of initial request
  public async checkAcr(operation: Operation, body: NodeJS.Dict<any>): Promise<boolean> {
    const credentials: Credentials = await this.credentialsExtractor.getCredentials(body);
    this.logger.info(`Extracted credentials: ${JSON.stringify(credentials)}`);

    const requestedModes = await this.modesExtractor.handleSafe(operation);
    this.logger.info(`Retrieved required modes: ${
      [ ...requestedModes.entrySets() ].map(([ id, set ]): string => `{ ${id.path}: ${[ ...set ]} }`)
    }`);

    const availablePermissions = await this.permissionReader.handleSafe({ credentials, requestedModes });
    this.logger.info(`Available permissions are ${
      [ ...availablePermissions.entries() ].map(([ id, map ]): string => `{ ${id.path}: ${JSON.stringify(map)} }`)
    }`);

    // Return true if any permissions are available to this combination of user/app/issuer as this means there is a match
    return [ ...availablePermissions.values() ].some(value => value.read === true);
  }

  public async extractNonceAndDomain(request: HttpRequest): Promise<any> {
    let nonceAndDomain = {};
    try {
      nonceAndDomain = await this.vpChecker.extractNonceAndDomain(request);
    } catch (error) {
      throw error;
    }
    return nonceAndDomain;
  }

  public async extractNonceAndDomainFromNew(request: HttpRequest): Promise<any> {
    const z: any = JSON.parse(request.headers.vp as string ?? '{}');
    let presentationParsedLocal: W3cJsonLdVerifiablePresentation | undefined;
    if (z.wrappedVP !== undefined) {
      /* It is a wrapper, check both the signature of the user and the signature of the app */
      const wrappedVP = JsonTransformer.fromJSON(z, W3cWrappedVerifiablePresentation);
      presentationParsedLocal = wrappedVP.wrappedVP as W3cJsonLdVerifiablePresentation;
    } else {
      presentationParsedLocal = JsonTransformer.fromJSON(z, W3cJsonLdVerifiablePresentation);
    }
    let nonceAndDomain = {};
    nonceAndDomain = await this.vpChecker.extractNonceAndDomainFromNew(presentationParsedLocal);

    return nonceAndDomain;
  }

  public async getCredentials(body: NodeJS.Dict<any>): Promise<Credentials> {
    return this.credentialsExtractor.getCredentials(body);
  }
}
