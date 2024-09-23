import { describe, expect, test } from 'vitest';
import { IoTransaction } from 'topl_common';
import TransactionSyntax from '@/brambl/syntax/transaction_syntax.js';
import ContainsSignable from '@/brambl/common/contains_signable.js';
import bs58 from 'bs58'
import { ContainsImmutable } from '@/index.js';

describe('TransactionCodecVectorsSpec', () => {
    vectors.forEach((vector, index) => {
        test(`Vector ${index}`, () => {
            const txBytes = hexToBytes(vector.txHex);
            const tx = IoTransaction.fromBinary(txBytes);
            const signable = ContainsSignable.ioTransaction(tx).signableBytes;
            const signableHex = bytesToHex(signable.value);
            console.log(signableHex);
            console.log(vector.txSignableHex);
            expect(signableHex).toEqual(vector.txSignableHex);
            // TODO: How to use syntax?
            expect("t_" + bs58.encode(new TransactionSyntax(tx).computeId().value)).toEqual(vector.txId);
        });

    })
});

describe.skip('Foo', () => {
    test('bar', () => {
        const tx = IoTransaction.fromBinary(hexToBytes(vectors[0].txHex));
        const b = ContainsSignable.ioTransaction(tx);
        const h = bytesToHex(b.signableBytes.value);
        const expected = "0000";
        console.log(h);
        console.log(expected)
        expect(expected).toEqual(h);
    });
})

const vectors = [
    {
        txHex: "1a060a040a002200",
        txSignableHex: "0000",
        txId: "t_BhHbw2zXrJGgRW9YpKQV4c6sXfSwChXeYrRjW1aCQqRF"
    },
    {
        txHex: "0a360a2422220a207b4ffd7c46c3884c6095e58a2eb4b28b610d6c3fd5a3297831f828a443d466a012040a020a001a080a060a040a0201f412340a28080510321a220a207b40522d25601601b7c859f735195500cc906183ae108dbc6e8a33b672bae97c12080a060a040a0201f41a060a040a002200",
        txSignableHex: "00000000696f5f7472616e73616374696f6e5f33327b4ffd7c46c3884c6095e58a2eb4b28b610d6c3fd5a3297831f828a443d466a00001f4000532626f785f6c6f636b5f33327b40522d25601601b7c859f735195500cc906183ae108dbc6e8a33b672bae97c01f40000",
        txId: "t_DeXDSTN9JCDb6RAvL3iGaX68fFtEm4gHFYtYMT6BEWwN"
    },
    {
        txHex: "0a3d0a2b0808104318d90222220a2082d4b6b33397ec74b6394284db2f2be79a6a950c3f0863347a79d2e2b92830d912040a020a001a0812060a040a0201f412340a28080510321a220a20897af2e0eb81f85365ff98f6578516973d96b0109fbc63c4ed8c7ecf1d6e751412080a060a040a0201f41a3c0a3a0a1408b11210ffffffffffffffff7f18fba1caf9a13222220a209d252954ade1c5909d397d97db968db897c8e663d94594ff4d7567fde9e6efc0",
        txSignableHex: "0008430159696f5f7472616e73616374696f6e5f333282d4b6b33397ec74b6394284db2f2be79a6a950c3f0863347a79d2e2b92830d90001f4ff000532626f785f6c6f636b5f3332897af2e0eb81f85365ff98f6578516973d96b0109fbc63c4ed8c7ecf1d6e751401f409317fffffffffffffff9d252954ade1c5909d397d97db968db897c8e663d94594ff4d7567fde9e6efc0",
        txId: "t_FvhubX87rvQvcMiUAVtiowyLaNGh2atx8P8cAeFWj5h7"
    }
]

function hexToBytes(hex: string): Uint8Array {
    return Uint8Array.from(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

function bytesToHex(bytes: Uint8Array): string {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}