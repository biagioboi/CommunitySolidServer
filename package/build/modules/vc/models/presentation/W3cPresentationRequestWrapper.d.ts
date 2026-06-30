import type { W3cJsonPresentation } from './W3cJsonPresentation';
import type { JsonObject } from '../../../../types';
import type { ValidationOptions } from 'class-validator';
import { SingleOrArray } from '../../../../utils/type';
import { W3cPresentationRequest } from ".";
import type { AcpPolicy } from '@sphereon/pex-models';
import { LinkedDataProof, LinkedDataProofOptions } from "../../data-integrity/models/LinkedDataProof";
import { DataIntegrityProof, DataIntegrityProofOptions } from '../../data-integrity/models';
export interface W3cPresentationWrapperOptions {
    id?: string;
    context?: Array<string | JsonObject>;
    type?: Array<string>;
    wrappedVPR: W3cPresentationRequest;
    termsAndCondition: AcpPolicy;
    proof?: SingleOrArray<LinkedDataProofOptions | DataIntegrityProofOptions>;
}
export declare class W3cPresentationRequestWrapper {
    constructor(options: W3cPresentationWrapperOptions);
    context: Array<string | JsonObject>;
    id?: string;
    type: Array<string>;
    wrappedVPR: W3cPresentationRequest;
    termsAndCondition?: AcpPolicy;
    proof?: SingleOrArray<LinkedDataProof | DataIntegrityProof>;
    toJSON(): W3cJsonPresentation;
}
export declare function IsVerifiablePresentationRequestWrapperType(validationOptions?: ValidationOptions): PropertyDecorator;
