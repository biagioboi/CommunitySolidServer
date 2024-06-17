import type { Agent,
  W3cCredentialSubject,
  W3cJsonLdVerifiableCredential } from '@credo-ts/core';
import {
  JsonTransformer,
  W3cJsonLdVerifiablePresentation,
} from '@credo-ts/core';
import { LinkedDataProof } from '@credo-ts/core/build/modules/vc/data-integrity/models/LinkedDataProof';
import { decodeJWT } from 'did-jwt';
import { verifyCredential, verifyPresentation } from 'did-jwt-vc';
import { Resolver } from 'did-resolver';
import { getResolver } from 'web-did-resolver';
import { AgentInitializer } from '../init/AgentInitializer';
import { getLoggerFor } from '../logging/LogUtil';
import type { HttpRequest } from '../server/HttpRequest';
import { BadRequestHttpError } from '../util/errors/BadRequestHttpError';
import type { Credentials } from './Credentials';
import { CredentialsExtractor } from './CredentialsExtractor';

export class VpChecker extends CredentialsExtractor {
  protected readonly logger = getLoggerFor(this);

  public constructor() {
    super();
  }

  public async canHandle({ headers }: HttpRequest): Promise<void> {
    if (headers.vp === undefined) {
      throw new BadRequestHttpError('No VP header specified.');
    }
  }

  public async handle(request: HttpRequest): Promise<Credentials> {
    try {
      const agent = new AgentInitializer().agent;
      await agent.initialize();
      // Const { webid: webId, client_id: clientId, iss: issuer } = await this.verify(request);
      /* The VC should contains the clientID, like if it is the termsAndConditions */
      const resp = await this.verifyNew(request, agent);
      this.logger.info(`Verified credentials via VP. WebID: ${resp.agent}
      }, client ID: ${resp.client}, issuer: ${resp.issuer}`);

      return resp;
    } catch (error: unknown) {
      const message = `Error verifying WebID via VP: ${(error as Error).message}`;
      this.logger.warn(message);
      throw new BadRequestHttpError(message, { cause: error });
    }
  }

  public async extractNonceAndDomain(request: HttpRequest): Promise<any> {
    const VP = request.headers.vp?.toString();
    if (VP) {
      try {
        const payload = decodeJWT(VP).payload;
        const nonce = payload.nonce;
        const domain = payload.domain;
        return { nonce, domain };
      } catch {
        throw new Error('Cannot decode VP JWT.');
      }
    }
  }

  public async extractNonceAndDomainFromNew(presentation: W3cJsonLdVerifiablePresentation): Promise<any> {
    let challenge = '';
    let domain = '';
    if (presentation.proof instanceof LinkedDataProof) {
      challenge = presentation.proof.challenge!;
      domain = presentation.proof.domain!;
    }
    return { challenge, domain };
  }

  // Verify the vp - should be received as a jwt contained within the header
  // If valid, extract the issuer and user and return as credentials. Else throw error
  public async verify(request: HttpRequest) {
    this.logger.info('Verifying VP...');
    const vpJwt: any = request.headers.vp;
    const resolver = new Resolver(getResolver());
    // Check expiry date of VP
    const now = Math.ceil(Date.now() / 1000);
    const VpPayload = decodeJWT(vpJwt).payload;
    if (VpPayload.exp !== undefined && VpPayload.exp < now) {
      this.logger.warn(`VP expired. Time now: ${now}, Expiry Date: ${VpPayload.exp}`);
      throw new Error(`VP has expired.`);
    }

    const verifiedVP = await verifyPresentation(vpJwt, resolver);
    // Check VP is valid
    const validVP = verifiedVP.verified;
    this.logger.info(`Verified? : ${validVP}`);
    console.log(verifiedVP.payload);

    this.logger.info('Verifying VC...');
    // Extract the VC from the JWT VP payload and check it is valid
    const vcJwt = verifiedVP.payload.vp.verifiableCredential[0];
    const verifiedVC = await verifyCredential(vcJwt, resolver);
    const validVC = verifiedVC.verified;
    this.logger.info(`Verified? : ${validVC}`);
    console.log(verifiedVC.payload);

    let clientId: any;
    if (VpPayload.appName) {
      clientId = VpPayload.appName;
    }
    // The agent is the subject of the VC
    const webid: any = verifiedVC.payload.sub;
    // The issuer is the issuer of the VC
    const iss: any = verifiedVC.payload.iss;
    return { webid, client_id: clientId, iss };
  }

  public async verifyNew(request: HttpRequest, agent: Agent): Promise<Credentials> {
    const z: any = JSON.parse(request.headers.vp as string ?? '{}');

    const presentationParsed = JsonTransformer.fromJSON(z, W3cJsonLdVerifiablePresentation);
    const vc = presentationParsed.verifiableCredential as W3cJsonLdVerifiableCredential[];
    /* It is possible to have multiple VCs in a single VPR, (intesto come tante vc non solo tanti attributi) */
    const credSubject = vc[0].credentialSubject as W3cCredentialSubject;
    const holderDid = credSubject.id!;
    const issuerDid = vc[0].issuer as string;
    const associatedProof = presentationParsed.proof as LinkedDataProof;
    const check = await agent.w3cCredentials.verifyPresentation({
      presentation: presentationParsed,
      challenge: associatedProof.challenge!,
      domain: associatedProof.domain!,
    });

    /**
     * TODO: Implement the method for getting the ACP field, instead of working with toJson
     */
    const objPresParsed = presentationParsed.toJson();
    const receivedAcp = objPresParsed.definedACPContext;
    if (check.isValid) {
      return { agent: holderDid, client: receivedAcp.client, issuer: issuerDid };
    }
    throw new Error(`Signature not valid. Error = ${check.error}`);
  }
}
