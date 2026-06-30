"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IsVerifiablePresentationRequestWrapperType = exports.W3cPresentationRequestWrapper = void 0;
const class_transformer_1 = require("class-transformer");
const class_validator_1 = require("class-validator");
const utils_1 = require("../../../../utils");
const validators_1 = require("../../../../utils/validators");
const constants_1 = require("../../constants");
const validators_2 = require("../../validators");
const LinkedDataProof_1 = require("../../data-integrity/models/LinkedDataProof");
const models_1 = require("../../data-integrity/models");
const ProofTransformer_1 = require("../../data-integrity/models/ProofTransformer");
class W3cPresentationRequestWrapper {
    constructor(options) {
        var _a, _b;
        if (options) {
            this.context = (_a = options.context) !== null && _a !== void 0 ? _a : [constants_1.WRAPPER_VERIFIABLE_PRESENTATION_REQUEST_URL];
            this.id = options.id;
            this.type = (_b = options.type) !== null && _b !== void 0 ? _b : [constants_1.WRAPPER_VERIFIABLE_PRESENTATION_REQUEST_TYPE];
            this.wrappedVPR = options.wrappedVPR;
            this.termsAndCondition = options.termsAndCondition;
            this.proof = options.proof;
        }
    }
    toJSON() {
        return utils_1.JsonTransformer.toJSON(this);
    }
}
__decorate([
    (0, class_transformer_1.Expose)({ name: '@context' }),
    (0, validators_2.IsCredentialJsonLdContext)(),
    __metadata("design:type", Array)
], W3cPresentationRequestWrapper.prototype, "context", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, validators_1.IsUri)(),
    __metadata("design:type", String)
], W3cPresentationRequestWrapper.prototype, "id", void 0);
__decorate([
    IsVerifiablePresentationRequestWrapperType(),
    __metadata("design:type", Array)
], W3cPresentationRequestWrapper.prototype, "type", void 0);
__decorate([
    (0, ProofTransformer_1.ProofTransformer)(),
    (0, validators_1.IsInstanceOrArrayOfInstances)({ classType: [LinkedDataProof_1.LinkedDataProof, models_1.DataIntegrityProof] }),
    (0, class_validator_1.ValidateNested)(),
    __metadata("design:type", Object)
], W3cPresentationRequestWrapper.prototype, "proof", void 0);
exports.W3cPresentationRequestWrapper = W3cPresentationRequestWrapper;
// Custom validators
function IsVerifiablePresentationRequestWrapperType(validationOptions) {
    return (0, class_validator_1.ValidateBy)({
        name: 'IsVerifiablePresentationRequestWrapperType',
        validator: {
            validate: (value) => {
                if (Array.isArray(value)) {
                    return value.includes(constants_1.WRAPPER_VERIFIABLE_PRESENTATION_REQUEST_TYPE);
                }
                return false;
            },
            defaultMessage: (0, class_validator_1.buildMessage)((eachPrefix) => eachPrefix + '$property must be an array of strings which includes "VerifiablePresentationRequestWrapper"', validationOptions),
        },
    }, validationOptions);
}
exports.IsVerifiablePresentationRequestWrapperType = IsVerifiablePresentationRequestWrapperType;
//# sourceMappingURL=W3cPresentationRequestWrapper.js.map