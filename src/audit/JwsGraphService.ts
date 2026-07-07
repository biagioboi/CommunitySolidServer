import { createHash } from 'crypto';
import { ensureDir, pathExists, readFile, readdir, writeFile } from 'fs-extra';
import { DataFactory, Store } from 'n3';
import type { Quad, Term } from 'rdf-js';
import { guardedStreamFrom, readableToString } from '../util/StreamUtil';
import { joinFilePath, trimLeadingSlashes } from '../util/PathUtil';
import { parseQuads, serializeQuads } from '../util/QuadUtil';
import { createVocabulary, DC, RDF, XSD } from '../util/Vocabularies';

const { literal, namedNode, quad } = DataFactory;

const JWS_AUDIT = createVocabulary('urn:solid-server:jws-audit#',
  'VerifiedJwsRecord',
  'requestedResource',
  'requesterDid',
  'messageHash',
  'connectionId',
  'verifiedAt',
  'signedResourceJson',
  'signedResourceType',
  'signerId',
  'jwsJson',
  'signerKid',
);

export interface JwsGraphServiceArgs {
  rootFilePath: string;
  relativeDirectory?: string;
}

export interface StoreVerifiedJwsArgs {
  signedResource?: Record<string, unknown>;
  signedResourceType?: 'jws' | 'vc';
  signerId?: string;
  jws?: Record<string, unknown>;
  requestedResource: string;
  requesterDid: string;
  messageHash: string;
  connectionId?: string;
  verifiedAt?: string;
}

export interface FindVerifiedJwsArgs {
  requestedResource?: string;
  requesterDid?: string;
}

export interface StoredVerifiedJwsRecord {
  id: string;
  signedResource: Record<string, unknown>;
  signedResourceType: 'jws' | 'vc';
  requestedResource: string;
  requesterDid: string;
  messageHash: string;
  verifiedAt: string;
  connectionId?: string;
  signerId?: string;
  jws?: Record<string, unknown>;
  signerKid?: string;
}

export class JwsGraphService {
  private readonly recordsDirectory: string;

  public constructor(args: JwsGraphServiceArgs) {
    const relativeDirectory = trimLeadingSlashes(args.relativeDirectory ?? '.internal/jws-audit/records');
    this.recordsDirectory = joinFilePath(args.rootFilePath, relativeDirectory);
  }

  public async storeVerifiedJws(args: StoreVerifiedJwsArgs): Promise<StoredVerifiedJwsRecord> {
    const verifiedAt = args.verifiedAt ?? new Date().toISOString();
    const signedResource = args.signedResource ?? args.jws;
    if (!signedResource) {
      throw new Error('A verified audit record requires a signedResource or legacy jws payload.');
    }

    const signedResourceType = args.signedResourceType ?? this.detectSignedResourceType(signedResource);
    const signerId = args.signerId ?? this.extractSignerId(signedResource, signedResourceType);
    const record: StoredVerifiedJwsRecord = {
      id: this.createRecordId(args, verifiedAt, signedResource, signedResourceType),
      signedResource,
      signedResourceType,
      requestedResource: args.requestedResource,
      requesterDid: args.requesterDid,
      messageHash: args.messageHash,
      verifiedAt,
      connectionId: args.connectionId,
      signerId,
      jws: signedResourceType === 'jws' ? signedResource : undefined,
      signerKid: signedResourceType === 'jws' ? signerId : undefined,
    };

    await ensureDir(this.recordsDirectory);
    const turtle = await readableToString(serializeQuads(this.recordToQuads(record), 'text/turtle'));
    await writeFile(this.getRecordFilePath(record.id), turtle, 'utf8');

    return record;
  }

  public async findVerifiedJws(args: FindVerifiedJwsArgs = {}): Promise<StoredVerifiedJwsRecord[]> {
    if (!await pathExists(this.recordsDirectory)) {
      return [];
    }

    const files = (await readdir(this.recordsDirectory))
      .filter((file): boolean => file.endsWith('.ttl'))
      .sort();

    const records = await Promise.all(files.map(async(file): Promise<StoredVerifiedJwsRecord> =>
      this.readRecord(joinFilePath(this.recordsDirectory, file))));

    return records.filter((record): boolean => (
      (!args.requestedResource || record.requestedResource === args.requestedResource) &&
      (!args.requesterDid || record.requesterDid === args.requesterDid)
    ));
  }

  private getRecordFilePath(id: string): string {
    return joinFilePath(this.recordsDirectory, `${id}.ttl`);
  }

  private createRecordId(
    args: StoreVerifiedJwsArgs,
    verifiedAt: string,
    signedResource: Record<string, unknown>,
    signedResourceType: 'jws' | 'vc',
  ): string {
    return createHash('sha256')
      .update(JSON.stringify({
        connectionId: args.connectionId ?? '',
        messageHash: args.messageHash,
        requestedResource: args.requestedResource,
        requesterDid: args.requesterDid,
        signedResource,
        signedResourceType,
        verifiedAt,
      }))
      .digest('hex');
  }

  private detectSignedResourceType(signedResource: Record<string, unknown>): 'jws' | 'vc' {
    const type = signedResource.type;
    if (typeof type === 'string') {
      return type === 'VerifiableCredential' ? 'vc' : 'jws';
    }

    return Array.isArray(type) && type.includes('VerifiableCredential') ? 'vc' : 'jws';
  }

  private extractSignerId(signedResource: Record<string, unknown>, signedResourceType: 'jws' | 'vc'): string | undefined {
    if (signedResourceType === 'vc') {
      const proof = Array.isArray(signedResource.proof) ? signedResource.proof[0] : signedResource.proof;
      if (proof && typeof proof === 'object' && typeof (proof as Record<string, unknown>).verificationMethod === 'string') {
        return (proof as Record<string, unknown>).verificationMethod as string;
      }

      return typeof signedResource.issuer === 'string' ? signedResource.issuer : undefined;
    }

    const header = typeof signedResource.header === 'object' && signedResource.header
      ? signedResource.header as Record<string, unknown>
      : undefined;
    return typeof header?.kid === 'string' ? header.kid : undefined;
  }

  private recordToQuads(record: StoredVerifiedJwsRecord): Quad[] {
    const subject = namedNode(`urn:solid-server:jws-audit:record:${record.id}`);
    const quads: Quad[] = [
      quad(subject, RDF.terms.type, JWS_AUDIT.terms.VerifiedJwsRecord),
      quad(subject, JWS_AUDIT.terms.requestedResource, namedNode(record.requestedResource)),
      quad(subject, JWS_AUDIT.terms.requesterDid, namedNode(record.requesterDid)),
      quad(subject, JWS_AUDIT.terms.messageHash, literal(record.messageHash)),
      quad(subject, JWS_AUDIT.terms.verifiedAt, literal(record.verifiedAt, XSD.terms.dateTime)),
      quad(subject, JWS_AUDIT.terms.signedResourceJson, literal(JSON.stringify(record.signedResource))),
      quad(subject, JWS_AUDIT.terms.signedResourceType, literal(record.signedResourceType)),
      quad(subject, DC.terms.modified, literal(record.verifiedAt, XSD.terms.dateTime)),
    ];

    if (record.connectionId) {
      quads.push(quad(subject, JWS_AUDIT.terms.connectionId, literal(record.connectionId)));
    }

    if (record.signerId) {
      quads.push(quad(subject, JWS_AUDIT.terms.signerId, literal(record.signerId)));
    }

    if (record.jws) {
      quads.push(quad(subject, JWS_AUDIT.terms.jwsJson, literal(JSON.stringify(record.jws))));
    }

    if (record.signerKid) {
      quads.push(quad(subject, JWS_AUDIT.terms.signerKid, literal(record.signerKid)));
    }

    return quads;
  }

  private async readRecord(filePath: string): Promise<StoredVerifiedJwsRecord> {
    const turtle = await readFile(filePath, 'utf8');
    const quads = await parseQuads(guardedStreamFrom(turtle), { format: 'text/turtle' });
    return this.quadsToRecord(quads);
  }

  private quadsToRecord(quads: Quad[]): StoredVerifiedJwsRecord {
    const store = new Store(quads);
    const subject = store.getSubjects(RDF.terms.type, JWS_AUDIT.terms.VerifiedJwsRecord, null)[0];
    if (!subject) {
      throw new Error('Could not find a signed resource audit subject in the stored graph.');
    }

    const requestedResource = this.getRequiredValue(store, subject, JWS_AUDIT.terms.requestedResource);
    const requesterDid = this.getRequiredValue(store, subject, JWS_AUDIT.terms.requesterDid);
    const messageHash = this.getRequiredValue(store, subject, JWS_AUDIT.terms.messageHash);
    const verifiedAt = this.getRequiredValue(store, subject, JWS_AUDIT.terms.verifiedAt);
    const signedResourceJson = this.getOptionalValue(store, subject, JWS_AUDIT.terms.signedResourceJson)
      ?? this.getRequiredValue(store, subject, JWS_AUDIT.terms.jwsJson);
    const signedResourceType = (this.getOptionalValue(store, subject, JWS_AUDIT.terms.signedResourceType) ?? 'jws') as 'jws' | 'vc';
    const connectionId = this.getOptionalValue(store, subject, JWS_AUDIT.terms.connectionId);
    const signerId = this.getOptionalValue(store, subject, JWS_AUDIT.terms.signerId)
      ?? this.getOptionalValue(store, subject, JWS_AUDIT.terms.signerKid);
    const signerKid = this.getOptionalValue(store, subject, JWS_AUDIT.terms.signerKid);
    const signedResource = JSON.parse(signedResourceJson) as Record<string, unknown>;

    return {
      id: subject.value.replace('urn:solid-server:jws-audit:record:', ''),
      signedResource,
      signedResourceType,
      requestedResource,
      requesterDid,
      messageHash,
      verifiedAt,
      connectionId,
      signerId,
      jws: signedResourceType === 'jws' ? signedResource : undefined,
      signerKid,
    };
  }

  private getRequiredValue(store: Store, subject: Term, predicate: Term): string {
    const value = this.getOptionalValue(store, subject, predicate);
    if (!value) {
      throw new Error(`Missing required signed resource audit field ${predicate.value}.`);
    }
    return value;
  }

  private getOptionalValue(store: Store, subject: Term, predicate: Term): string | undefined {
    const object = store.getObjects(subject, predicate, null)[0];
    return object?.value;
  }
}
