import type { HttpResponse } from '../../../server/HttpResponse';
import { addHeader } from '../../../util/HeaderUtil';
import { SOLID_HTTP } from '../../../util/Vocabularies';
import type { RepresentationMetadata } from '../../representation/RepresentationMetadata';
import { MetadataWriter } from './MetadataWriter';

/**
 * Adds the `encryptedresource`/`keyfordecrypt` headers when the corresponding metadata is present,
 * regardless of the response status code. Used by the non-repudiable read release flow.
 */
export class NonRepudiationMetadataWriter extends MetadataWriter {
  public async handle(input: { response: HttpResponse; metadata: RepresentationMetadata }): Promise<void> {
    const encryptedResource = input.metadata.get(SOLID_HTTP.terms.encryptedResource)?.value;
    if (encryptedResource !== undefined) {
      addHeader(input.response, 'encryptedresource', encryptedResource);
    }
    const keyForDecrypt = input.metadata.get(SOLID_HTTP.terms.keyForDecrypt)?.value;
    if (keyForDecrypt !== undefined) {
      addHeader(input.response, 'keyfordecrypt', keyForDecrypt);
    }
  }
}
