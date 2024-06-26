import { ensureTrailingSlash, joinUrl } from '../../util/PathUtil';
import type { KeyValueStorage } from './KeyValueStorage';

/**
 * Transforms the keys into relative paths, to be used by the source storage.
 * Encodes the input key with base64 encoding,
 * to make sure there are no invalid or special path characters,
 * and prepends it with the stored relative path.
 * This can be useful to eventually generate URLs in specific containers
 * without having to worry about cleaning the input keys.
 */
export class EncodingPathStorage<T> implements KeyValueStorage<string, T> {
  protected readonly basePath: string;
  protected readonly source: KeyValueStorage<string, T>;

  public constructor(relativePath: string, source: KeyValueStorage<string, T>) {
    this.source = source;
    this.basePath = ensureTrailingSlash(relativePath);
  }

  public async get(key: string): Promise<T | undefined> {
    const path = this.keyToPath(key);
    return this.source.get(path);
  }

  public async has(key: string): Promise<boolean> {
    const path = this.keyToPath(key);
    return this.source.has(path);
  }

  public async set(key: string, value: T): Promise<this> {
    const path = this.keyToPath(key);
    await this.source.set(path, value);
    return this;
  }

  public async delete(key: string): Promise<boolean> {
    const path = this.keyToPath(key);
    return this.source.delete(path);
  }

  public async* entries(): AsyncIterableIterator<[string, T]> {
    for await (const [ path, value ] of this.source.entries()) {
      // The only relevant entries for this storage are those that start with the base path
      if (!path.startsWith(this.basePath)) {
        continue;
      }
      const key = this.pathToKey(path);
      yield [ key, value ];
    }
  }

  /**
   * Converts a key into a path for internal storage.
   */
  protected keyToPath(key: string): string {
    const encodedKey = Buffer.from(key).toString('base64');
    return joinUrl(this.basePath, encodedKey);
  }

  /**
   * Converts an internal storage path string into the original path key.
   */
  protected pathToKey(path: string): string {
    // While the main part of a base64 encoded string is same from any changes from encoding or decoding URL parts,
    // the `=` symbol that is used for padding is not.
    // This can cause incorrect results when calling these function,
    // where the original path contains `YXBwbGU%3D` instead of `YXBwbGU=`.
    // This does not create any issues when the source store does not encode the string, so is safe to always call.
    // For consistency, we might want to also always encode when creating the path in `keyToPath()`,
    // but that would potentially break existing implementations that do not do encoding,
    // and is not really necessary to solve any issues.
    const buffer = Buffer.from(decodeURIComponent(path.slice(this.basePath.length)), 'base64');
    return buffer.toString('utf-8');
  }
}
