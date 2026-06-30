import type { DifPexInputDescriptorToCredentials, DifPexCredentialsForRequest, DifPresentationExchangeDefinitionV1 } from '../../../dif-presentation-exchange';
import type { W3cJsonPresentation } from '../../../vc/models/presentation/W3cJsonPresentation';
import type { W3cPresentationRequest } from '../../../vc/models/';
import type { ProofFormat } from '../ProofFormat';
export type DifPresentationExchangeProposal = DifPresentationExchangeDefinitionV1;
export interface DifPexGetCredentialsForProofRequestOptions {
}
export type DifPresentationExchangeRequest = {
    '@context'?: [string];
    type?: [string];
    options?: {
        challenge?: string;
        domain?: string;
    };
    presentation_definition: DifPresentationExchangeDefinitionV1;
};
export type DifPresentationExchangePresentation = W3cJsonPresentation | string;
export interface DifPresentationExchangeProofFormat extends ProofFormat {
    formatKey: 'presentationExchange';
    proofFormats: {
        createProposal: {
            presentationDefinition: DifPresentationExchangeDefinitionV1;
        };
        acceptProposal: {
            options?: {
                challenge?: string;
                domain?: string;
            };
        };
        createRequest: {
            '@context'?: [string];
            type?: [string];
            presentationDefinition: DifPresentationExchangeDefinitionV1;
            options?: {
                challenge?: string;
                domain?: string;
            };
            signPresentationRequest: boolean;
            signACPContext: boolean;
        };
        acceptRequest: {
            credentials?: DifPexInputDescriptorToCredentials;
        };
        getCredentialsForRequest: {
            input: DifPexGetCredentialsForProofRequestOptions;
            output: DifPexCredentialsForRequest;
        };
        selectCredentialsForRequest: {
            input: DifPexGetCredentialsForProofRequestOptions;
            output: {
                credentials: DifPexInputDescriptorToCredentials;
            };
        };
    };
    formatData: {
        proposal: DifPresentationExchangeProposal;
        request: W3cPresentationRequest;
        presentation: DifPresentationExchangePresentation;
    };
}
