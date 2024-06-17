import { getLoggerFor } from '../logging/LogUtil';
import type { Credentials } from './Credentials';


/**
 * Simple Credentials extractor that can extract User, App and Issuer from body of HTTP request.
 */
export class VcExtractor {
  protected readonly logger = getLoggerFor(this);

  public constructor() {

  }

  public async getCredentials(body: NodeJS.Dict<any>): Promise<Credentials>{
    const credentials: Credentials = {
      issuer: body.issuer,
      client: body.client,
      agent: body.agent,
    };
    return credentials;
  }
}
