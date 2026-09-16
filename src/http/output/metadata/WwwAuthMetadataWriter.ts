import type { HttpResponse } from '../../../server/HttpResponse';
import { addHeader } from '../../../util/HeaderUtil';
import { HTTP, SOLID_HTTP } from '../../../util/Vocabularies';
import type { RepresentationMetadata } from '../../representation/RepresentationMetadata';
import { MetadataWriter } from './MetadataWriter';

/**
 * Adds the `WWW-Authenticate` header with the injected value in case the response status code is 401.
 */
export class WwwAuthMetadataWriter extends MetadataWriter {
  private readonly auth: string;

  public constructor(auth: string) {
    super();
    this.auth = auth;
  }

  public async handle(input: { response: HttpResponse; metadata: RepresentationMetadata }): Promise<void> {
    const statusLiteral = input.metadata.get(HTTP.terms.statusCodeNumber);
    const customAuth = input.metadata.get(SOLID_HTTP.terms.wwwAuthenticate)?.value;
    if (statusLiteral?.value === '401') {
      addHeader(input.response, 'WWW-Authenticate', customAuth ?? this.auth);
    }
  }
}
