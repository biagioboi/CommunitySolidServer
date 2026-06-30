import type { StoreCredentialOptions, W3cCreatePresentationOptions, W3cSignCredentialOptions, W3cSignPresentationOptions, W3cVerifyCredentialOptions, W3cSignWrappedPresentationRequestOptions, W3cVerifyPresentationOptions, W3cCreatePresentationWrapperOptions, W3cCreatePresentationRequestWrapperOptions, W3cVerifyWrappedPresentationOptions } from './W3cCredentialServiceOptions';
import type { W3cVerifiableCredential, ClaimFormat } from './models';
import type { W3cCredentialRecord } from './repository';
import type { Query } from '../../storage/StorageService';
import { AgentContext } from '../../agent';
import { W3cCredentialService } from './W3cCredentialService';
import { W3cSignWrappedPresentationOptions } from "./W3cCredentialServiceOptions";
import { W3cSignPresentationRequestOptions } from "./W3cPresentationRequestServiceOptions";
import { W3cPresentationRequest } from "./models";
/**
 * @public
 */
export declare class W3cCredentialsApi {
    private agentContext;
    private w3cCredentialService;
    constructor(agentContext: AgentContext, w3cCredentialService: W3cCredentialService);
    storeCredential(options: StoreCredentialOptions): Promise<W3cCredentialRecord>;
    removeCredentialRecord(id: string): Promise<void>;
    getAllCredentialRecords(): Promise<W3cCredentialRecord[]>;
    getCredentialRecordById(id: string): Promise<W3cCredentialRecord>;
    findCredentialRecordsByQuery(query: Query<W3cCredentialRecord>): Promise<W3cVerifiableCredential[]>;
    signCredential<Format extends ClaimFormat.JwtVc | ClaimFormat.LdpVc>(options: W3cSignCredentialOptions<Format>): Promise<W3cVerifiableCredential<Format>>;
    verifyCredential(options: W3cVerifyCredentialOptions): Promise<import("./models").W3cVerifyCredentialResult>;
    createPresentation(options: W3cCreatePresentationOptions): Promise<import("./models").W3cPresentation>;
    createPresentationWrapper(options: W3cCreatePresentationWrapperOptions): Promise<import("./models").W3cPresentationWrapper>;
    createPresentationRequestWrapper(options: W3cCreatePresentationRequestWrapperOptions): Promise<import("./models/presentation/W3cPresentationRequestWrapper").W3cPresentationRequestWrapper>;
    signPresentation<Format extends ClaimFormat.JwtVp | ClaimFormat.LdpVp>(options: W3cSignPresentationOptions<Format>): Promise<import("./models").W3cVerifiablePresentation<Format>>;
    signPresentationRequest(options: W3cSignPresentationRequestOptions): Promise<W3cPresentationRequest>;
    signWrappedPresentation(options: W3cSignWrappedPresentationOptions): Promise<import("./data-integrity").W3cWrappedVerifiablePresentation>;
    signWrappedPresentationRequest(options: W3cSignWrappedPresentationRequestOptions): Promise<import("./models/presentation/W3cPresentationRequestWrapper").W3cPresentationRequestWrapper>;
    verifyPresentation(options: W3cVerifyPresentationOptions): Promise<import("./models").W3cVerifyPresentationResult>;
    verifyWrappedPresentation(options: W3cVerifyWrappedPresentationOptions): Promise<import("./models").W3cVerifyPresentationResult>;
}
