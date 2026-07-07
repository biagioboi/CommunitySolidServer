import { JwsGraphHttpHandler } from '../../../src/server/JwsGraphHttpHandler';
import { readableToString } from '../../../src/util/StreamUtil';
import type { JwsGraphService } from '../../../src/audit/JwsGraphService';
import type { ErrorHandler } from '../../../src/http/output/error/ErrorHandler';
import type { ResponseWriter } from '../../../src/http/output/ResponseWriter';
import { ResponseDescription } from '../../../src/http/output/response/ResponseDescription';
import { StaticAsyncHandler } from '../../util/StaticAsyncHandler';

describe('A JwsGraphHttpHandler', (): void => {
  let errorHandler: ErrorHandler;
  let responseWriter: jest.Mocked<ResponseWriter>;
  let jwsGraphService: jest.Mocked<JwsGraphService>;
  let handler: JwsGraphHttpHandler;

  beforeEach(async(): Promise<void> => {
    errorHandler = new StaticAsyncHandler(true, new ResponseDescription(500));
    responseWriter = {
      handleSafe: jest.fn(),
    } as any;
    jwsGraphService = {
      findVerifiedJws: jest.fn().mockResolvedValue([
        {
          connectionId: 'conn-1',
          id: 'record-1',
          signedResource: { type: [ 'VerifiableCredential' ] },
          signedResourceType: 'vc',
          messageHash: 'a'.repeat(64),
          requestedResource: 'http://example.com/private/report',
          requesterDid: 'did:web:alice.example',
          signerId: 'did:web:secureapp.solidcommunity.net:public#key-1',
          verifiedAt: '2026-07-06T10:00:00.000Z',
        },
      ]),
    } as any;

    handler = new JwsGraphHttpHandler({
      baseUrl: 'http://example.com/',
      errorHandler,
      jwsGraphService,
      responseWriter,
    });
  });

  it('only handles the reserved JWS audit route.', async(): Promise<void> => {
    await expect(handler.canHandle({
      request: {
        method: 'GET',
        url: '/.internal/jws-audit/query?requesterDid=did:web:alice.example',
      } as any,
      response: {} as any,
    })).resolves.toBeUndefined();

    await expect(handler.canHandle({
      request: {
        method: 'GET',
        url: '/other',
      } as any,
      response: {} as any,
    })).rejects.toThrow();
  });

  it('forwards query filters to the JWS graph service and returns JSON.', async(): Promise<void> => {
    await handler.handle({
      request: {
        method: 'GET',
        url: '/.internal/jws-audit/query?resource=http%3A%2F%2Fexample.com%2Fprivate%2Freport&requesterDid=did%3Aweb%3Aalice.example',
      } as any,
      response: {} as any,
    });

    expect(jwsGraphService.findVerifiedJws).toHaveBeenCalledWith({
      requestedResource: 'http://example.com/private/report',
      requesterDid: 'did:web:alice.example',
    });

    const result = responseWriter.handleSafe.mock.calls[0][0].result;
    expect(result.statusCode).toBe(200);

    const body = await readableToString(result.data!);
    expect(JSON.parse(body)).toEqual({
      count: 1,
      records: [
        expect.objectContaining({
          requestedResource: 'http://example.com/private/report',
          requesterDid: 'did:web:alice.example',
        }),
      ],
    });
  });
});
