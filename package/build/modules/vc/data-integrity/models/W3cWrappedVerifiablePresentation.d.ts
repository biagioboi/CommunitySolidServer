import type { DataIntegrityProofOptions } from './DataIntegrityProof';
import type { LinkedDataProofOptions } from './LinkedDataProof';
import type { W3cPresentationWrapperOptions } from '../../models/presentation/W3cPresentationWrapper';
import { SingleOrArray } from '../../../../utils';
import { ClaimFormat } from '../../models';
import { W3cPresentationWrapper } from '../../models/presentation/W3cPresentationWrapper';
import { DataIntegrityProof } from './DataIntegrityProof';
import { LinkedDataProof } from './LinkedDataProof';
export interface W3cWrappedVerifiablePresentationOptions extends W3cPresentationWrapperOptions {
    proof: LinkedDataProofOptions | DataIntegrityProofOptions;
}
export declare class W3cWrappedVerifiablePresentation extends W3cPresentationWrapper {
    constructor(options: W3cWrappedVerifiablePresentationOptions);
    proof: SingleOrArray<LinkedDataProof | DataIntegrityProof>;
    get proofTypes(): Array<string>;
    get dataIntegrityCryptosuites(): Array<string>;
    toJson(): Record<string, any>;
    /**
     * The {@link ClaimFormat} of the presentation. For JSON-LD credentials this is always `ldp_vp`.
     */
    get claimFormat(): ClaimFormat.LdpVp;
    /**
     * Get the encoded variant of the W3C Verifiable Presentation. For JSON-LD presentations this is
     * a JSON object.
     */
    get encoded(): Record<string, any>;
}
