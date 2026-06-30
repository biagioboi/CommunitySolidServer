import type { W3cHolderOptions } from './W3cHolder';
import type { W3cJsonPresentation } from './W3cJsonPresentation';
import type { JsonObject } from '../../../../types';
import type { ValidationOptions } from 'class-validator';
import type { W3cVerifiablePresentation } from '.';
import { W3cHolder } from './W3cHolder';
export interface W3cPresentationWrapperOptions {
    id?: string;
    context?: Array<string | JsonObject>;
    type?: Array<string>;
    wrappedVP: W3cVerifiablePresentation;
    holder?: string | W3cHolderOptions;
}
export declare class W3cPresentationWrapper {
    constructor(options: W3cPresentationWrapperOptions);
    context: Array<string | JsonObject>;
    id?: string;
    type: Array<string>;
    holder?: string | W3cHolder;
    wrappedVP: W3cVerifiablePresentation;
    get holderId(): string | null;
    toJSON(): W3cJsonPresentation;
}
export declare function IsVerifiablePresentationWrapperType(validationOptions?: ValidationOptions): PropertyDecorator;
