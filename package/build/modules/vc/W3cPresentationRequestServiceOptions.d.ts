import type { ProofPurpose } from './data-integrity';
import type { ClaimFormat } from './models';
import { DifPresentationExchangeDefinition } from "../dif-presentation-exchange";
import type { AcpPolicy } from '@sphereon/pex-models';
export type W3cSignPresentationRequestOptions = W3cJsonLdSignPresentationRequestOptions;
export type W3cSignACPContextOptions = W3cJsonLdSignACPContextOptions;
interface W3cSignPresentationRequestOptionsBase {
    /**
     * The format of the credential to be signed.
     *
     * @see https://identity.foundation/claim-format-registry
     */
    format: ClaimFormat;
    /**
     * The credential to be signed.
     */
    presentationRequest: {
        '@context': string[];
        type: string[];
        presentation_definition: DifPresentationExchangeDefinition;
        options: {
            challenge: string;
            domain: string;
        };
    };
    /**
     * URI of the verificationMethod to be used for signing the credential.
     *
     * Must be a valid did url pointing to a key.
     */
    verificationMethod: string;
}
export interface W3cJsonLdSignPresentationRequestOptions extends W3cSignPresentationRequestOptionsBase {
    /**
     * The format of the credential to be signed. Must be either `jwt_vc` or `ldp_vc`.
     * @see https://identity.foundation/claim-format-registry
     */
    format: ClaimFormat.LdpVc;
    /**
     * The proofType to be used for signing the credential.
     *
     * Must be a valid Linked Data Signature suite.
     */
    proofType: string;
    proofPurpose?: ProofPurpose;
    created?: string;
}
interface W3cSignACPContextOptionsBase {
    /**
     * The format of the credential to be signed.
     *
     * @see https://identity.foundation/claim-format-registry
     */
    format: ClaimFormat;
    /**
     * The credential to be signed.
     */
    acpPolicy: {
        '@context': string[];
        type: string[];
        definedACPContext: AcpPolicy;
    };
    challenge: string;
    domain: string;
    /**
     * URI of the verificationMethod to be used for signing the credential.
     *
     * Must be a valid did url pointing to a key.
     */
    verificationMethod: string;
}
export interface W3cJsonLdSignACPContextOptions extends W3cSignACPContextOptionsBase {
    /**
     * The format of the credential to be signed. Must be either `jwt_vc` or `ldp_vc`.
     * @see https://identity.foundation/claim-format-registry
     */
    format: ClaimFormat.LdpVc;
    /**
     * The proofType to be used for signing the credential.
     *
     * Must be a valid Linked Data Signature suite.
     */
    proofType: string;
    proofPurpose?: ProofPurpose;
    created?: string;
}
export {};
