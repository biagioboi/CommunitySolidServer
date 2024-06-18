import type {V2RequestPresentationMessage} from '@credo-ts/core';
import type {RequestParser} from '../http/input/RequestParser';
import type {ErrorHandler} from '../http/output/error/ErrorHandler';
import {ResponseDescription} from '../http/output/response/ResponseDescription';
import type {ResponseWriter} from '../http/output/ResponseWriter';
import {BasicRepresentation} from '../http/representation/BasicRepresentation';
import {AgentInitializer} from '../init/AgentInitializer';
import {getLoggerFor} from '../logging/LogUtil';
import {assertError} from '../util/errors/ErrorUtil';
import {HttpError} from '../util/errors/HttpError';
import {readJsonStream} from '../util/StreamUtil';
import type {HttpHandlerInput} from './HttpHandler';
import {HttpHandler} from './HttpHandler';
import type {HttpRequest} from './HttpRequest';
import type {HttpResponse} from './HttpResponse';
import type {VcAuthorizingHttpHandler} from './VcAuthorizingHttpHandler';

export interface VcHttpHandlerArgs {
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
export class VcHttpHandler extends HttpHandler {
    private readonly logger = getLoggerFor(this);

    private readonly requestParser: RequestParser;
    private readonly errorHandler: ErrorHandler;
    private readonly responseWriter: ResponseWriter;

    private readonly operationHandler: VcAuthorizingHttpHandler;
    private readonly nonceDomainMap: Map<any, any>;
    private readonly agentInitializer: AgentInitializer;

    public constructor(args: VcHttpHandlerArgs) {
        super();
        this.requestParser = args.requestParser;
        this.errorHandler = args.errorHandler;
        this.responseWriter = args.responseWriter;
        this.operationHandler = args.operationHandler;
        this.nonceDomainMap = new Map<any, any>();
        this.agentInitializer = new AgentInitializer();
        this.agentInitializer.agent.initialize().then().catch(e => this.logger.info('Errore'));
    }

    public async handle({request, response}: HttpHandlerInput): Promise<void> {
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
            return await this.responseWriter.handleSafe({response, result});
        }
    }

    // This handler will only respond to requests that have:
    // -'vc' header (Initial Request)
    // -'vp' header (Secondary Request/Verifiable Presentation)
    public async canHandle({request, response}: HttpHandlerInput): Promise<void> {
        if ((request.headers.vc === undefined) &&
            (request.headers.vp === undefined)) {
            throw new Error('Required headers missing: \'VC\' or \'VP\'.');
        }
    }

    /**
     * Interprets the request and generates a response description that can be used by the ResponseWriter to respond
     */
    public async handleRequest(request: HttpRequest, response: HttpResponse, body?: NodeJS.Dict<any>):
        Promise<ResponseDescription> {
        const operation = await this.requestParser.handleSafe(request);

        // Handle if it is the initial request
        if ((request.headers.vc !== undefined) && body && this.isInitialRequest(body)) {
            this.logger.info('Detected Initial Request');
            if (await this.validUserAppIssuer(request, body)) {
                return this.isRequestingVPCompliant(body) ? await this.handleInitialRequestCompliant(request, body) : await this.handleInitialRequest(request, body);
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
        const result = await this.errorHandler.handleSafe({error, request});
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
        const ourDID = this.agentInitializer.did;
        // Store nonce and domain in the map
        this.nonceDomainMap.set(nonce, `https://bboi.solidcommunity.net/definition/ourProtocol#test`);
        const result: ResponseDescription = new ResponseDescription(401);
        const VPrequest = {
            VerifiablePresentation: {
                query: {
                    type: 'QueryByExample',
                    credentialQuery: {
                        reason: 'We need you to prove your eligibility.',
                        owner: {
                            id: ourDID,
                        },
                        issuer: {
                            id: body.issuer,
                        },
                        client: {
                            id: body.client,
                        },
                        agent: {
                            id: body.agent,
                        },
                    },
                },
                challenge: nonce,
                domain: `https://bboi.solidcommunity.net/definition/ourProtocol#test`,
            },
        };
        const representation = new BasicRepresentation(JSON.stringify(VPrequest), 'application/ld+json');
        result.data = representation.data;

        return result;
    }

    // Deal with the initial request and respond with a VP Request
    // @ts-ignore
    public async handleInitialRequestCompliant(request: HttpRequest, body: NodeJS.Dict<any>): Promise<ResponseDescription> {
        const crypto = require('crypto');
        const nonce = crypto.randomBytes(16).toString('base64');
        this.logger.info(`Generated Nonce: ${nonce}`);
        const uri = request.url;
        // Store nonce and domain in the map
        this.nonceDomainMap.set(nonce, `http://localhost:3000${uri}`);
        const result: ResponseDescription = new ResponseDescription(401);

        /* If you want, I can generate also a more professional VPR, using the agent */
        const {message: msg} = await this.agentInitializer.agent.proofs.createRequest({
            protocolVersion: 'v2',
            proofFormats: {
                presentationExchange: {
                    '@context': [ 'https://bboi.solidcommunity.net/public/schemas/2024/presexchange.jsonld' ],
                    type: [ 'VerifiablePresentationRequest' ],
                    presentationDefinition: {
                        "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                        "input_descriptors": [
                            {
                                "id": "unisa_student",
                                "name": "University of Salerno Demo",
                                "purpose": "Demonstrate to be a student from the University of Salerno to access this POD",
                                "constraints": {
                                    "fields": [
                                        {
                                            "path": [
                                                "$.credentialSubject.degree",
                                                "$.credentialSubject.claims.degree",
                                            ]
                                        }
                                    ]
                                }
                            }
                        ],
                        "format": { // Which format we want for the signature? Currently, we are using ldp_vp
                            "ldp_vc": {
                                "proof_type": [
                                    "JsonWebSignature2020",
                                    "Ed25519Signature2018",
                                    "EcdsaSecp256k1Signature2019",
                                    "RsaSignature2018"
                                ]
                            },
                            "ldp_vp": {
                                "proof_type": ["Ed25519Signature2018"]
                            },
                            "ldp": {
                                "proof_type": ["RsaSignature2018"]
                            }
                        },
                        "requestACP": {
                            "type": ["ACPContext"],
                            "target": `http://localhost:3000${uri}`,
                            "owner": this.agentInitializer.did, // We should revise also this one .. maybe the server doesn't have a pod but have a proper space
                            "issuer": body.issuer,
                            "client": body.client,
                            "agent": body.agent,
                        }
                    },
                    options: {
                        challenge: nonce,
                        domain: `https://bboi.solidcommunity.net/definition/ourProtocol#context`,
                    },
                    signPresentationRequest: false

        },

            },
        });

        const rpMsg = msg as V2RequestPresentationMessage;
        const k = rpMsg.requestAttachments[0].data.json!
        /* But it is up to you, only if you really want, ps. the presentation is not a graph */
        result.data = new BasicRepresentation(JSON.stringify(k), 'application/json').data;

        return result;
    }

    public async handleSecondRequest(request: HttpRequest, response: HttpResponse): Promise<ResponseDescription> {
        const operation = await this.requestParser.handleSafe(request);
        try {
            const result = await this.operationHandler.handle({operation, request, response});
            const {challenge} = await this.operationHandler.extractNonceAndDomainFromNew(request);
            this.nonceDomainMap.delete(challenge);
            return result;
        } catch (error: unknown) {
            throw error;
        }
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
