import { Context } from 'fabric-contract-api';
import { ChaincodeStub, Iterators } from 'fabric-shim';

export class MockStateQueryIterator implements Iterators.StateQueryIterator {
  private items: Array<{ key: string; value: Buffer }>;
  private currentIndex: number = 0;

  constructor(items: Array<{ key: string; value: Buffer }>) {
    this.items = items;
  }

  public async next(): Promise<Iterators.NextResult<Iterators.KV>> {
    if (this.currentIndex < this.items.length) {
      const item = this.items[this.currentIndex++];
      return {
        value: {
          namespace: '',
          key: item.key,
          value: item.value
        },
        done: false
      };
    }
    return {
      value: undefined as any,
      done: true
    };
  }

  public async close(): Promise<void> {
    this.currentIndex = this.items.length;
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<Iterators.KV> {
    return this as any;
  }
}

export class MockStub {
  private state: Map<string, Buffer> = new Map();
  private txTimestamp: { seconds: { low: number; high: number } } = {
    seconds: { low: 1760250000, high: 0 }
  };

  public setTxTimestamp(epochSeconds: number): void {
    this.txTimestamp = {
      seconds: { low: epochSeconds, high: 0 }
    };
  }

  public getTxTimestamp(): any {
    return this.txTimestamp;
  }

  public async getState(key: string): Promise<Buffer> {
    return this.state.get(key) || Buffer.alloc(0);
  }

  public async putState(key: string, value: Buffer): Promise<void> {
    this.state.set(key, value);
  }

  public async deleteState(key: string): Promise<void> {
    this.state.delete(key);
  }

  public createCompositeKey(objectType: string, attributes: string[]): string {
    return `\x00${objectType}\x00${attributes.join('\x00')}\x00`;
  }

  public splitCompositeKey(compositeKey: string): { objectType: string; attributes: string[] } {
    const parts = compositeKey.split('\x00').filter((p) => p.length > 0);
    return {
      objectType: parts[0] || '',
      attributes: parts.slice(1)
    };
  }

  public async getStateByPartialCompositeKey(
    objectType: string,
    attributes: string[]
  ): Promise<MockStateQueryIterator> {
    const prefix = `\x00${objectType}\x00${attributes.length > 0 ? attributes.join('\x00') + '\x00' : ''}`;
    const matched: Array<{ key: string; value: Buffer }> = [];

    for (const [k, v] of this.state.entries()) {
      if (k.startsWith(prefix)) {
        matched.push({ key: k, value: v });
      }
    }

    return new MockStateQueryIterator(matched);
  }

  public getInternalState(): Map<string, Buffer> {
    return this.state;
  }
}

export function createMockContext(epochSeconds: number = 1760250000): Context {
  const stub = new MockStub();
  stub.setTxTimestamp(epochSeconds);

  return {
    stub: stub as unknown as ChaincodeStub,
    clientIdentity: {
      getID: () => 'x509::CN=Kelly::OU=client',
      getMSPID: () => 'Org1MSP',
      getAttributeValue: () => null,
      assertAttributeValue: () => true,
      getX509Certificate: () => ({ subject: { commonName: 'Kelly' } })
    }
  } as unknown as Context;
}
