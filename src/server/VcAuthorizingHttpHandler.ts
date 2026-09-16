import {
    Agent,
    JsonTransformer,
    W3cJsonLdVerifiablePresentation,
    W3cWrappedVerifiablePresentation
} from '@credo-ts/core';
import type {Credentials} from '../authentication/Credentials';
import type {VcExtractor} from '../authentication/VcExtractor';
import type {VpChecker} from '../authentication/VpChecker';
import type {Authorizer} from '../authorization/Authorizer';
import type {PermissionReader} from '../authorization/PermissionReader';
import type {ModesExtractor} from '../authorization/permissions/ModesExtractor';
import type {Operation} from '../http/Operation';
import {RepresentationMetadata} from '../http/representation/RepresentationMetadata';
import {ResponseDescription} from '../http/output/response/ResponseDescription';
import {AgentInitializer} from '../init/AgentInitializer';
import {getLoggerFor} from '../logging/LogUtil';
import {readableToString} from '../util/StreamUtil';
import {toLiteral} from '../util/TermUtil';
import {HTTP, SOLID_HTTP, XSD} from '../util/Vocabularies';
import type {HttpRequest} from './HttpRequest';
import type {OperationHttpHandlerInput} from './OperationHttpHandler';
import {OperationHttpHandler} from './OperationHttpHandler';

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
    /**
     * Used to build the encrypted, non-repudiable release when only acl:NRRead is granted.
     * Optional: when absent (e.g. AgentInitializer's own internal operationHandler, to avoid a
     * circular Component.js dependency), the handler falls back to serving the resource directly.
     */
    agentInitializer?: AgentInitializer;
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
    private readonly agentInitializer?: AgentInitializer;

    public constructor(args: VcAuthorizingHttpHandlerArgs) {
        super();
        this.credentialsExtractor = args.credentialsExtractor;
        this.vpChecker = args.vpChecker;
        this.modesExtractor = args.modesExtractor;
        this.permissionReader = args.permissionReader;
        this.authorizer = args.authorizer;
        this.operationHandler = args.operationHandler;
        this.agentInitializer = args.agentInitializer;
    }

    // Uses the VpChecker component to verify the VP, extracts credentials from a valid VP
    // Checks the extracted credentials against the acr file for the requested resource
    public async handle(input: OperationHttpHandlerInput): Promise<ResponseDescription> {
        const {request, operation} = input;
        /* Just for testing purpose */
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
            [...requestedModes.entrySets()].map(([id, set]): string => `{ ${id.path}: ${[...set]} }`)
        }`);

        const availablePermissions = await this.permissionReader.handleSafe({credentials, requestedModes});
        this.logger.info(`Available permissions are ${
            [...availablePermissions.entries()].map(([id, map]): string => `{ ${id.path}: ${JSON.stringify(map)} }`)
        }`);

        try {
            await this.authorizer.handleSafe({credentials, requestedModes, availablePermissions});
        } catch (error: unknown) {
            this.logger.info(`Authorization failed: ${(error as any).message}`);
            throw error;
        }
        this.logger.info(`Authorization succeeded, calling source handler`);

        const permissionSet = availablePermissions.get(operation.target);
        if (this.agentInitializer && permissionSet?.read !== true && permissionSet?.nonRepudiableRead === true) {
            return this.handleNonRepudiableRelease(input, credentials);
        }

        return this.operationHandler.handleSafe(input);
    }

    // Only acl:NRRead is granted (not plain acl:Read): instead of serving the resource directly,
    // encrypt it for the TTP escrow, attach the NRO evidence, and return it as the `encryptedresource`
    // header. The App must complete a follow-up release (via the CSS or directly via the TTP) to
    // obtain the decryption key - see VcDidCommHttpHandler.handleReleaseRequest.
    private async handleNonRepudiableRelease(input: OperationHttpHandlerInput, credentials: Credentials):
    Promise<ResponseDescription> {
        const plainResponse = await this.operationHandler.handleSafe(input);
        const plaintext = await readableToString(plainResponse.data!);
        const {encryptedMessage} = await this.agentInitializer!.buildNonRepudiableRelease(
            credentials.agent ?? '', input.operation.target.path, plaintext,
        );

        const metadata = new RepresentationMetadata();
        metadata.add(HTTP.terms.statusCodeNumber, toLiteral(200, XSD.terms.integer));
        metadata.add(SOLID_HTTP.terms.encryptedResource, JSON.stringify(encryptedMessage));
        return new ResponseDescription(200, metadata);
    }

    // Check acr has appropriate combo for user, app, issuer
    // Uses VcExtractor and just takes these values from body of initial request
    public async checkAcr(operation: Operation, body: NodeJS.Dict<any>): Promise<boolean> {
        const credentials: Credentials = await this.credentialsExtractor.getCredentials(body);
        this.logger.info(`Extracted credentials: ${JSON.stringify(credentials)}`);
        console.log("Testing operation:", operation);
        const requestedModes = await this.modesExtractor.handleSafe(operation);
        
        this.logger.info(`Retrieved required modes: ${
            [...requestedModes.entrySets()].map(([id, set]): string => `{ ${id.path}: ${[...set]} }`)
        }`);

        const availablePermissions = await this.permissionReader.handleSafe({credentials, requestedModes});
        this.logger.info(`Available permissions are ${
            [...availablePermissions.entries()].map(([id, map]): string => `{ ${id.path}: ${JSON.stringify(map)} }`)
        }`);

        // Return true if any permissions are available to this combination of user/app/issuer as this means there is a match
        return [...availablePermissions.values()].some(value => value.read === true || value.nonRepudiableRead === true);
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

    // Checks whether the target resource of the operation only grants public read access
    // through the non-repudiable read mode (acl:NRRead), meaning a normal, unauthenticated
    // request should be challenged with the DID flow instead of a plain 401/403.
    //
    // Note: an acl:NRRead policy is almost always scoped to specific agent/issuer/client matchers
    // (via acp:allOf), which never match anonymous credentials - so "does anonymous have
    // nonRepudiableRead" is always false and can't be used to detect this case. Instead, when the
    // permission reader exposes a structural check (currently only AcpReader does), use that to see
    // whether the resource has an acl:NRRead policy AT ALL, regardless of who is asking.
    public async requiresNonRepudiableRead(operation: Operation): Promise<boolean> {
        const {target} = operation;
        const requestedModes = await this.modesExtractor.handleSafe(operation);
        const availablePermissions = await this.permissionReader.handleSafe({credentials: {}, requestedModes});
        const anonymousPermissions = availablePermissions.get(target);

        // Anonymous already has plain read - no need for a DID challenge.
        if (anonymousPermissions?.read === true) {
            return false;
        }

        const structuralCheck = (this.permissionReader as {requiresNonRepudiableRead?: (id: typeof target) => Promise<boolean>})
            .requiresNonRepudiableRead;
        if (typeof structuralCheck === 'function') {
            return structuralCheck.call(this.permissionReader, target);
        }

        return anonymousPermissions?.nonRepudiableRead === true;
    }
}
