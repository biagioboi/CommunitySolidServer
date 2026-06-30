import type { JsonObject } from '../../../../types';
import { SingleOrArray } from '../../../../utils/type';
import { LinkedDataProof, LinkedDataProofOptions } from "../../data-integrity/models/LinkedDataProof";
import { DataIntegrityProof, DataIntegrityProofOptions } from '../../data-integrity/models';
import { DifPresentationExchangeDefinition } from "../../../dif-presentation-exchange";
export interface W3cPresentationRequestOptions {
    id?: string;
    context?: Array<string | JsonObject>;
    type?: Array<string>;
    presentation_definition: DifPresentationExchangeDefinition;
    options: {
        challenge: string;
        domain: string;
    };
    proof?: SingleOrArray<LinkedDataProofOptions | DataIntegrityProofOptions>;
}
export declare class W3cPresentationRequest {
    constructor(options: W3cPresentationRequestOptions);
    context: Array<string | JsonObject>;
    id?: string;
    options: JsonObject | undefined;
    presentation_definition: DifPresentationExchangeDefinition;
    type: Array<string>;
    issuanceDate: string;
    proof?: SingleOrArray<LinkedDataProof | DataIntegrityProof>;
    toJSON(): W3cPresentationRequest;
}
