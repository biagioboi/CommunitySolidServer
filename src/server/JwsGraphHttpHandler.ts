import type { ErrorHandler } from '../http/output/error/ErrorHandler';
import { ResponseDescription } from '../http/output/response/ResponseDescription';
import type { ResponseWriter } from '../http/output/ResponseWriter';
import { BasicRepresentation } from '../http/representation/BasicRepresentation';
import { JwsGraphService } from '../audit/JwsGraphService';
import { getLoggerFor } from '../logging/LogUtil';
import { joinUrl } from '../util/PathUtil';
import { assertError } from '../util/errors/ErrorUtil';
import { HttpError } from '../util/errors/HttpError';
import { MethodNotAllowedHttpError } from '../util/errors/MethodNotAllowedHttpError';
import { NotImplementedHttpError } from '../util/errors/NotImplementedHttpError';
import type { HttpHandlerInput } from './HttpHandler';
import { HttpHandler } from './HttpHandler';
import type { HttpRequest } from './HttpRequest';

export interface JwsGraphHttpHandlerArgs {
  errorHandler: ErrorHandler;
  responseWriter: ResponseWriter;
  jwsGraphService: JwsGraphService;
  baseUrl: string;
}

export class JwsGraphHttpHandler extends HttpHandler {
  private readonly logger = getLoggerFor(this);
  private readonly errorHandler: ErrorHandler;
  private readonly responseWriter: ResponseWriter;
  private readonly jwsGraphService: JwsGraphService;
  private readonly queryPath: string;
  private readonly baseUrl: string;

  public constructor(args: JwsGraphHttpHandlerArgs) {
    super();
    this.errorHandler = args.errorHandler;
    this.responseWriter = args.responseWriter;
    this.jwsGraphService = args.jwsGraphService;
    this.baseUrl = args.baseUrl;
    this.queryPath = new URL(joinUrl(args.baseUrl, '.internal/jws-audit/query')).pathname;
  }

  public async canHandle({ request }: HttpHandlerInput): Promise<void> {
    const requestUrl = this.parseRequestUrl(request);
    if (requestUrl.pathname !== this.queryPath) {
      throw new NotImplementedHttpError(`No signed resource audit handler configured for ${requestUrl.pathname}.`);
    }
    if (request.method !== 'GET') {
      throw new MethodNotAllowedHttpError([ 'GET' ], 'Signed resource audit queries only support GET.');
    }
  }

  public async handle({ request, response }: HttpHandlerInput): Promise<void> {
    let result: ResponseDescription;

    try {
      const requestUrl = this.parseRequestUrl(request);
      const requestedResource = requestUrl.searchParams.get('resource') ?? undefined;
      const requesterDid = requestUrl.searchParams.get('requesterDid') ?? undefined;
      const records = await this.jwsGraphService.findVerifiedJws({ requestedResource, requesterDid });

      this.logger.info(`Returning ${records.length} signed resource audit record(s).`);
      result = new ResponseDescription(200);
      result.data = new BasicRepresentation(JSON.stringify({
        count: records.length,
        records,
      }), 'application/json').data;
    } catch (error: unknown) {
      result = await this.handleError(error, request);
    }

    await this.responseWriter.handleSafe({ response, result });
  }

  protected async handleError(error: unknown, request: HttpRequest): Promise<ResponseDescription> {
    assertError(error);
    const result = await this.errorHandler.handleSafe({ error, request });
    if (HttpError.isInstance(error) && result.metadata) {
      const quads = error.generateMetadata(result.metadata.identifier);
      result.metadata.addQuads(quads);
    }
    return result;
  }

  private parseRequestUrl(request: HttpRequest): URL {
    if (!request.url) {
      throw new NotImplementedHttpError('Missing request url.');
    }
    return new URL(request.url, this.baseUrl);
  }
}
