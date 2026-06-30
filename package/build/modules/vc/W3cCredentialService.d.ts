import type { StoreCredentialOptions, W3cCreatePresentationOptions, W3cSignCredentialOptions, W3cSignPresentationOptions, W3cVerifyCredentialOptions, W3cVerifyPresentationOptions, W3cSignWrappedPresentationOptions, W3cCreatePresentationRequestWrapperOptions, W3cVerifyWrappedPresentationOptions } from './W3cCredentialServiceOptions';
import type { W3cVerifiableCredential, W3cVerifiablePresentation, W3cVerifyCredentialResult, W3cVerifyPresentationResult } from './models';
import type { AgentContext } from '../../agent/context';
import type { Query } from '../../storage/StorageService';
import { W3cJsonLdCredentialService } from './data-integrity/W3cJsonLdCredentialService';
import { W3cWrappedVerifiablePresentation } from './data-integrity/models/W3cWrappedVerifiablePresentation';
import { W3cJwtCredentialService } from './jwt-vc/W3cJwtCredentialService';
import { ClaimFormat, W3cPresentationRequest, W3cPresentationWrapper } from './models';
import { W3cPresentation } from './models/presentation/W3cPresentation';
import { W3cCredentialRecord, W3cCredentialRepository } from './repository';
import { W3cSignACPContextOptions, W3cSignPresentationRequestOptions } from "../vc";
import { W3cCreatePresentationWrapperOptions, W3cSignWrappedPresentationRequestOptions } from "./W3cCredentialServiceOptions";
import { W3cPresentationRequestWrapper } from "./models/presentation/W3cPresentationRequestWrapper";
export declare class W3cCredentialService {
    private w3cCredentialRepository;
    private w3cJsonLdCredentialService;
    private w3cJwtCredentialService;
    constructor(w3cCredentialRepository: W3cCredentialRepository, w3cJsonLdCredentialService: W3cJsonLdCredentialService, w3cJwtCredentialService: W3cJwtCredentialService);
    /**
     * Signs a credential
     *
     * @param credential the credential to be signed
     * @returns the signed credential
     */
    signCredential<Format extends ClaimFormat.JwtVc | ClaimFormat.LdpVc>(agentContext: AgentContext, options: W3cSignCredentialOptions<Format>): Promise<W3cVerifiableCredential<Format>>;
    /**
     * Verifies the signature(s) of a credential
     */
    verifyCredential(agentContext: AgentContext, options: W3cVerifyCredentialOptions): Promise<W3cVerifyCredentialResult>;
    /**
     * Utility method that creates a {@link W3CPresentationWrapper} from one or more {@link W3cJsonLdVerifiableCredential}s.
     *
     * **NOTE: the presentation wrapper that is returned is unsigned.**
     *
     * @returns An instance of {@link W3cPresentationWrapper}
     */
    createPresentationRequestWrapper(options: W3cCreatePresentationRequestWrapperOptions): Promise<W3cPresentationRequestWrapper>;
    /**
     * Utility method that creates a {@link W3cPresentation} from one or more {@link W3cJsonLdVerifiableCredential}s.
     *
     * **NOTE: the presentation that is returned is unsigned.**
     *
     * @returns An instance of {@link W3cPresentation}
     */
    createPresentation(options: W3cCreatePresentationOptions): Promise<W3cPresentation>;
    /**
     * Utility method that creates a {@link W3CPresentationWrapper} from one or more {@link W3cJsonLdVerifiableCredential}s.
     *
     * **NOTE: the presentation wrapper that is returned is unsigned.**
     *
     * @returns An instance of {@link W3cPresentationWrapper}
     */
    createPresentationWrapper(options: W3cCreatePresentationWrapperOptions): Promise<W3cPresentationWrapper>;
    /**
     * Signs a presentation including the credentials it includes
     *
     * @param presentation the presentation to be signed
     * @returns the signed presentation
     */
    signPresentation<Format extends ClaimFormat.JwtVp | ClaimFormat.LdpVp>(agentContext: AgentContext, options: W3cSignPresentationOptions<Format>): Promise<W3cVerifiablePresentation<Format>>;
    /**
     * Signs a presentation including the credentials it includes
     *
     * @param presentation the presentation to be signed
     * @returns the signed presentation
     */
    signWrappedPresentation(agentContext: AgentContext, options: W3cSignWrappedPresentationOptions): Promise<W3cWrappedVerifiablePresentation>;
    /**
     * Signs a presentation including the credentials it includes
     *
     * @param presentation the presentation to be signed
     * @returns the signed presentation
     */
    signWrappedPresentationRequest(agentContext: AgentContext, options: W3cSignWrappedPresentationRequestOptions): Promise<W3cPresentationRequestWrapper>;
    /**
     * Signs a presentation request
     *
     * @param presentation the presentation request to be signed
     * @returns the signed presentation
     */
    signPresentationRequest(agentContext: AgentContext, options: W3cSignPresentationRequestOptions): Promise<W3cPresentationRequest>;
    /**
     * Signs a presentation request
     *
     * @param presentation the presentation request to be signed
     * @returns the signed presentation
     */
    signACPContext(agentContext: AgentContext, options: W3cSignACPContextOptions): Promise<W3cPresentationRequest>;
    /**
     * Verifies a presentation including the credentials it includes
     *
     * @param presentation the presentation to be verified
     * @returns the verification result
     */
    verifyPresentation(agentContext: AgentContext, options: W3cVerifyPresentationOptions): Promise<W3cVerifyPresentationResult>;
    /**
     * Verifies a presentation including the credentials it includes
     *
     * @param presentation the presentation to be verified
     * @returns the verification result
     */
    verifyWrappedPresentation(agentContext: AgentContext, options: W3cVerifyWrappedPresentationOptions): Promise<W3cVerifyPresentationResult>;
    /**
     * Writes a credential to storage
     *
     * @param record the credential to be stored
     * @returns the credential record that was written to storage
     */
    storeCredential(agentContext: AgentContext, options: StoreCredentialOptions): Promise<W3cCredentialRecord>;
    removeCredentialRecord(agentContext: AgentContext, id: string): Promise<void>;
    getAllCredentialRecords(agentContext: AgentContext): Promise<W3cCredentialRecord[]>;
    getCredentialRecordById(agentContext: AgentContext, id: string): Promise<W3cCredentialRecord>;
    findCredentialsByQuery(agentContext: AgentContext, query: Query<W3cCredentialRecord>): Promise<W3cVerifiableCredential[]>;
    findCredentialRecordByQuery(agentContext: AgentContext, query: Query<W3cCredentialRecord>): Promise<W3cVerifiableCredential | undefined>;
}
