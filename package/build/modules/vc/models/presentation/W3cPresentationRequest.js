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
exports.W3cPresentationRequest = void 0;
const class_transformer_1 = require("class-transformer");
const class_validator_1 = require("class-validator");
const utils_1 = require("../../../../utils");
const validators_1 = require("../../../../utils/validators");
const constants_1 = require("../../constants");
const validators_2 = require("../../validators");
const LinkedDataProof_1 = require("../../data-integrity/models/LinkedDataProof");
const models_1 = require("../../data-integrity/models");
const ProofTransformer_1 = require("../../data-integrity/models/ProofTransformer");
class W3cPresentationRequest {
    constructor(options) {
        var _a, _b;
        if (options) {
            this.context = (_a = options.context) !== null && _a !== void 0 ? _a : [constants_1.VERIFIABLE_PRESENTATION_REQUEST_URL];
            this.type = (_b = options.type) !== null && _b !== void 0 ? _b : ["VerifiablePresentationRequest"];
            this.id = options.id;
            this.presentation_definition = options.presentation_definition;
            this.options = options.options;
            this.proof = options.proof;
        }
    }
    toJSON() {
        return utils_1.JsonTransformer.toJSON(this);
    }
}
__decorate([
    (0, class_transformer_1.Expose)({ name: '@context' }),
    (0, validators_2.IsVerifiablePresentationRequestJsonLdContext)(),
    __metadata("design:type", Array)
], W3cPresentationRequest.prototype, "context", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, validators_1.IsUri)(),
    __metadata("design:type", String)
], W3cPresentationRequest.prototype, "id", void 0);
__decorate([
    (0, ProofTransformer_1.ProofTransformer)(),
    (0, validators_1.IsInstanceOrArrayOfInstances)({ classType: [LinkedDataProof_1.LinkedDataProof, models_1.DataIntegrityProof] }),
    (0, class_validator_1.ValidateNested)(),
    __metadata("design:type", Object)
], W3cPresentationRequest.prototype, "proof", void 0);
exports.W3cPresentationRequest = W3cPresentationRequest;
// Custom validators
//# sourceMappingURL=W3cPresentationRequest.js.map