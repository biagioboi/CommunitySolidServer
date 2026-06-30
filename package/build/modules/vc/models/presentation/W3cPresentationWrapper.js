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
exports.IsVerifiablePresentationWrapperType = exports.W3cPresentationWrapper = void 0;
const class_transformer_1 = require("class-transformer");
const class_validator_1 = require("class-validator");
const utils_1 = require("../../../../utils");
const validators_1 = require("../../../../utils/validators");
const constants_1 = require("../../constants");
const validators_2 = require("../../validators");
const W3cHolder_1 = require("./W3cHolder");
class W3cPresentationWrapper {
    constructor(options) {
        var _a, _b;
        if (options) {
            this.context = (_a = options.context) !== null && _a !== void 0 ? _a : [constants_1.CREDENTIALS_CONTEXT_V1_URL, constants_1.WRAPPER_VP_CONTEXT_URL];
            this.id = options.id;
            this.type = (_b = options.type) !== null && _b !== void 0 ? _b : [constants_1.VERIFIABLE_PRESENTATION_TYPE];
            this.wrappedVP = options.wrappedVP;
            if (options.holder) {
                this.holder = typeof options.holder === 'string' ? options.holder : new W3cHolder_1.W3cHolder(options.holder);
            }
        }
    }
    get holderId() {
        if (!this.holder)
            return null;
        return this.holder instanceof W3cHolder_1.W3cHolder ? this.holder.id : this.holder;
    }
    toJSON() {
        return utils_1.JsonTransformer.toJSON(this);
    }
}
__decorate([
    (0, class_transformer_1.Expose)({ name: '@context' }),
    (0, validators_2.IsCredentialJsonLdContext)(),
    __metadata("design:type", Array)
], W3cPresentationWrapper.prototype, "context", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, validators_1.IsUri)(),
    __metadata("design:type", String)
], W3cPresentationWrapper.prototype, "id", void 0);
__decorate([
    IsVerifiablePresentationWrapperType(),
    __metadata("design:type", Array)
], W3cPresentationWrapper.prototype, "type", void 0);
__decorate([
    (0, W3cHolder_1.W3cHolderTransformer)(),
    (0, W3cHolder_1.IsW3cHolder)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Object)
], W3cPresentationWrapper.prototype, "holder", void 0);
exports.W3cPresentationWrapper = W3cPresentationWrapper;
// Custom validators
function IsVerifiablePresentationWrapperType(validationOptions) {
    return (0, class_validator_1.ValidateBy)({
        name: 'IsVerifiablePresentationWrapperType',
        validator: {
            validate: (value) => {
                if (Array.isArray(value)) {
                    return value.includes(constants_1.VERIFIABLE_PRESENTATION_TYPE);
                }
                return false;
            },
            defaultMessage: (0, class_validator_1.buildMessage)((eachPrefix) => eachPrefix + '$property must be an array of strings which includes "VerifiablePresentation"', validationOptions),
        },
    }, validationOptions);
}
exports.IsVerifiablePresentationWrapperType = IsVerifiablePresentationWrapperType;
//# sourceMappingURL=W3cPresentationWrapper.js.map