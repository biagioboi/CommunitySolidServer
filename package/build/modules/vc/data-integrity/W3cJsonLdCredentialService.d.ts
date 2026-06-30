import type { W3cJsonLdDeriveProofOptions } from './deriveProof';
import type { AgentContext } from '../../../agent/context';
import type { W3cJsonLdSignCredentialOptions, W3cJsonLdSignPresentationOptions, W3cJsonLdVerifyCredentialOptions, W3cJsonLdVerifyPresentationOptions, W3cVerifyWrappedPresentationOptions } from '../W3cCredentialServiceOptions';
import type { W3cVerifyCredentialResult, W3cVerifyPresentationResult } from '../models';
import { W3cCredentialsModuleConfig } from '../W3cCredentialsModuleConfig';
import { SignatureSuiteRegistry } from './SignatureSuiteRegistry';
import { W3cJsonLdVerifiableCredential, W3cWrappedVerifiablePresentation } from './models';
import { W3cJsonLdVerifiablePresentation } from './models/W3cJsonLdVerifiablePresentation';
import { W3cSignACPContextOptions, W3cSignPresentationRequestOptions } from '../../vc';
import { W3cPresentationRequest } from "../models";
import { W3cSignWrappedPresentationOptions, W3cSignWrappedPresentationRequestOptions } from "../W3cCredentialServiceOptions";
import { W3cPresentationRequestWrapper } from "../models/presentation/W3cPresentationRequestWrapper";
/**
 * Supports signing and verification of credentials according to the [Verifiable Credential Data Model](https://www.w3.org/TR/vc-data-model)
 * using [Data Integrity Proof](https://www.w3.org/TR/vc-data-model/#data-integrity-proofs).
 */
export declare class W3cJsonLdCredentialService {
    private signatureSuiteRegistry;
    private w3cCredentialsModuleConfig;
    constructor(signatureSuiteRegistry: SignatureSuiteRegistry, w3cCredentialsModuleConfig: W3cCredentialsModuleConfig);
    /**
     * Signs a credential
     */
    signCredential(agentContext: AgentContext, options: W3cJsonLdSignCredentialOptions): Promise<W3cJsonLdVerifiableCredential>;
    /**
     * Verifies the signature(s) of a credential
     *
     * @param credential the credential to be verified
     * @returns the verification result
     */
    verifyCredential(agentContext: AgentContext, options: W3cJsonLdVerifyCredentialOptions): Promise<W3cVerifyCredentialResult>;
    /**
     * Signs a presentation including the credentials it includes
     *
     * @param presentation the presentation to be signed
     * @returns the signed presentation
     */
    signPresentation(agentContext: AgentContext, options: W3cJsonLdSignPresentationOptions): Promise<W3cJsonLdVerifiablePresentation>;
    /**
     * Signs a presentation wrapper including the VP it includes
     *
     * @param presentation the presentation to be signed
     * @returns the signed presentation
     */
    signWrappedPresentation(agentContext: AgentContext, options: W3cSignWrappedPresentationOptions): Promise<W3cWrappedVerifiablePresentation>;
    /**
     * Signs a presentation request
     *
     * @param presentation the presentation to be signed (improperly used, it is a shortcome)
     * @returns the signed presentation
     */
    signPresentationRequest(agentContext: AgentContext, options: W3cSignPresentationRequestOptions): Promise<W3cPresentationRequest>;
    /**
     * Signs a presentation request
     *
     * @param presentation the presentation to be signed (improperly used, it is a shortcome)
     * @returns the signed presentation
     */
    signACPContext(agentContext: AgentContext, options: W3cSignACPContextOptions): Promise<W3cPresentationRequest>;
    /**
     * Signs a presentation request
     *
     * @param presentation the presentation to be signed (improperly used, it is a shortcome)
     * @returns the signed presentation
     */
    signWrappedPresentationRequest(agentContext: AgentContext, options: W3cSignWrappedPresentationRequestOptions): Promise<W3cPresentationRequestWrapper>;
    /**
     * Verifies a presentation including the credentials it includes
     *
     * @param presentation the presentation to be verified
     * @returns the verification result
     */
    verifyPresentation(agentContext: AgentContext, options: W3cJsonLdVerifyPresentationOptions): Promise<W3cVerifyPresentationResult>;
    /**
     * Verifies a Wrapped Presentation without checking the credentials
     *
     * @param presentation the wrapped presentation to be verified
     * @returns the verification result
     */
    verifyWrappedPresentation(agentContext: AgentContext, options: W3cVerifyWrappedPresentationOptions): Promise<W3cVerifyPresentationResult>;
    deriveProof(agentContext: AgentContext, options: W3cJsonLdDeriveProofOptions): Promise<W3cJsonLdVerifiableCredential>;
    getVerificationMethodTypesByProofType(proofType: string): string[];
    getKeyTypesByProofType(proofType: string): string[];
    getExpandedTypesForCredential(agentContext: AgentContext, credential: W3cJsonLdVerifiableCredential): Promise<string[]>;
    private getPublicKeyFromVerificationMethod;
    private getSignatureSuitesForCredential;
}
