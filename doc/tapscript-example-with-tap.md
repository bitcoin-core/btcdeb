# Tapscript example using Tap

The taproot branch of btcdeb contains experimental support for the work-in-progress Taproot proposal by Pieter Wuille and others. (See https://github.com/bitcoin/bitcoin/pull/17977)

This document is an early draft describing one process with which you can create, from scratch, your own Tapscript output, fund it, and then spend one of its paths.

This is the Tap version, which uses the new command line tool *tap* to do the heavy lifting. If you feel adventurous, you may want to check out [the nitty gritty version](tapscript-example.md) of this document (but recommend you do so after finishing this one).

## Scenario

We will base the approach on a simple [HTLC](https://en.bitcoin.it/wiki/Hash_Time_Locked_Contracts)-like contract between Alice and Bob, kind of like a Lightning channel. In old-style Bitcoin, this might look something like this:

```
OP_IF
    144
    OP_CHECKSEQUENCEVERIFY
    OP_DROP
    <pubkey_alice>
OP_ELSE
    OP_SHA256
    preimage_hash
    OP_EQUALVERIFY
    <pubkey_bob>
OP_ENDIF
OP_CHECKSIG
```

Either (1) Alice takes the money after waiting 1 day, or (2) Bob takes the money whenever he wishes to, by revealing preimage_hash. (This is an example of a cross-chain atomic swap, but we won't go into further details on that here.)

There are two downsides with the above script: (1) whenever Alice or Bob spends it, everyone in the world sees the whole script, so it's bad for *privacy*. And (2) the entire script must be pushed onto the blockchain, which is wasteful and costly. Enter Tapscript.

Tapscript lets us split the above into any number of script paths. We then put those into a Merkle tree, and when we spend the funds, we only reveal the merkle proof of inclusion of our specified path, and the satisfying conditions to it. We get two scripts:

```
1. 144 OP_CHECKSEQUENCEVERIFY OP_DROP <pubkey_alice> OP_CHECKSIG
2. OP_SHA256 preimage_hash OP_EQUALVERIFY <pubkey_bob> OP_CHECKSIG
```

Before we jump into that, let's make three key-pairs; Alice's keys, Bob's keys, and the internal key. You can make these inside btcdeb if you ran `./configure` with the `--enable-dangerous` flag (it's called dangerous because clueless people might be fooled into giving evil people private keys to real bitcoin; if you're here, you probably know enough to warrant enabling it).

Anyway, you can do that or just use mine (the sha256 of 'alice', 'bob', and 'internal' respectively):

```
Owner:      Key:                                                                Pubkey:
alice       2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90    9997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be
bob         81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9    4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
intrnl      1229101a0fcf2104e8808dab35661134aa5903867d44deb73ce1c7e4eb925be8    f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c

And preimage 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f with sha256(preimage) = 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
```

So the above two scripts expand into:
```
1. 144 OP_CHECKSEQUENCEVERIFY OP_DROP 9997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be OP_CHECKSIG
2. OP_SHA256 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 OP_EQUALVERIFY 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 OP_CHECKSIG
```

(now you might realize why people are so eager to *not* have to show all the paths when spending; not having to show the unnecessary alternative path(s) means a much smaller script and thus less fees)

Let's put the above stuff into environment variables so we can access them later:

```Bash
$ privkey=1229101a0fcf2104e8808dab35661134aa5903867d44deb73ce1c7e4eb925be8
$ pubkey=f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
$ script_alice='[144 OP_CHECKSEQUENCEVERIFY OP_DROP 9997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be OP_CHECKSIG]'
$ script_bob='[OP_SHA256 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 OP_EQUALVERIFY 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 OP_CHECKSIG]'
```

Next, we will see how we can generate an output for these (the output will be encumbered by the above scripts, and the internal key).

## Generating a Taproot commitment

Without going into detail, in order to spend a Taproot output, you either have to sign with the *tweaked private key* or you have to provide (1) a script, (2) a proof that the script was actually *committed to* by the output, and (3) conditions satisfying the script, including signatures and the like.

We will do both, in that order.

```Bash
$ tap $pubkey 2 $script_alice $script_bob
tap 0.2.19 -- type `tap -h` for help
WARNING: This is experimental software. Do not use this with real bitcoin, or you will most likely lose them all. You have been w a r n e d.
LOG: sign segwit taproot
Internal pubkey: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
2 scripts:
- #0: 029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac
- #1: a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
Script #0 leaf hash = TapLeaf<<0xc0 || 029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac>>
 → c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
Script #1 leaf hash = TapLeaf<<0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac>>
 → 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce943b42
Branch (#0, #1)
 → 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b
Tweak value = 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f1352607a9
Tweaked pubkey = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951 (not negated)
Resulting Bech32 address: sb1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsy7hxn9
```

The output is quite verbose right now, but lets go through what's being said here:
* There is an internal pubkey f30...; we provided this one (`$pubkey`)
* There are 2 scripts, the alice and bob scripts
* There are *leaf hashes* for each of the scripts; we will talk about these more when we do the Tapscript spend
* There's a branch for script #0 and #1 -- this simply ties the two scripts above together into a merkle tree
* There's a tweak value, which is based on the above merkle tree, and a tweaked pubkey, which is our given pubkey *tweaked* with the above tweak. To put it simply, we are applying our scripts to our pubkey, to form a new pubkey which commits to those scripts.
* Finally, there's a Bech32 address. This is where we wanna send funds. Let's send 0.001 signet-coins to it.

```Bash
$ alias bcli='bitcoin-cli -signet' # change this to whatever command you use to access bitcoin-cli
$ bcli sendtoaddress sb1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsy7hxn9 0.001
d4dcac1d176516dd614beef10eb7b22a666a69efcd3470b91423eca82e50f25e
$ bcli getrawtransaction d4dcac1d176516dd614beef10eb7b22a666a69efcd3470b91423eca82e50f25e 1
{
  "txid": "d4dcac1d176516dd614beef10eb7b22a666a69efcd3470b91423eca82e50f25e",
  "hash": "650385f0ad3e16b72e6024214664c0b53bf4eb5493d1a74e53d11bcc55582163",
  "version": 2,
  "size": 234,
  "vsize": 153,
  "weight": 609,
  "locktime": 582,
  "vin": [
    {
      "txid": "d4461a7d5d4120f7c3fd62c2f665b546129e4527a2bc2f1f7e7eedf4f77eba62",
      "vout": 1,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "304402202f11adb63ae0563d6cbb1955421c7081ac559319b924f1519b3e35b334c8721b02207436ed5d3b9490c7796ee4d4fe2a90f8697c49fb4b4a8531e9446a658cef2c7d01",
        "023f9b34f7749620702e1ade7d8f29f6d1d86122bc0dcf2aac6af1cc7cbb11d910"
      ],
      "sequence": 4294967294
    }
  ],
  "vout": [
    {
      "value": 0.00100000,
      "n": 0,
      "scriptPubKey": {
        "asm": "1 a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951",
        "hex": "5120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951",
        "reqSigs": 1,
        "type": "witness_unknown",
        "addresses": [
          "sb1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsy7hxn9"
        ]
      }
    },
    {
      "value": 49.99579079,
      "n": 1,
      "scriptPubKey": {
        "asm": "0 068d953d034da27b8affddb1e66240c2c0ccb30c",
        "hex": "0014068d953d034da27b8affddb1e66240c2c0ccb30c",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "sb1qq6xe20grfk38hzhlmkc7vcjqctqvevcvd5x8el"
        ]
      }
    }
  ],
  "hex": "0200000000010162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40100000000feffffff02a086010000000000225120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951c785ff2901000000160014068d953d034da27b8affddb1e66240c2c0ccb30c0247304402202f11adb63ae0563d6cbb1955421c7081ac559319b924f1519b3e35b334c8721b02207436ed5d3b9490c7796ee4d4fe2a90f8697c49fb4b4a8531e9446a658cef2c7d0121023f9b34f7749620702e1ade7d8f29f6d1d86122bc0dcf2aac6af1cc7cbb11d91046020000"
}
```

This will be our input transaction. Make note of the index in the vout array of our output -- in this case it is index 0. We need to keep that index and that hex value around, so let's save those as environment variables:
```Bash
$ vin=0 # CONFIRM THIS OR THINGS WILL FAIL
$ txin=0200000000010162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40100000000feffffff02a086010000000000225120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951c785ff2901000000160014068d953d034da27b8affddb1e66240c2c0ccb30c0247304402202f11adb63ae0563d6cbb1955421c7081ac559319b924f1519b3e35b334c8721b02207436ed5d3b9490c7796ee4d4fe2a90f8697c49fb4b4a8531e9446a658cef2c7d0121023f9b34f7749620702e1ade7d8f29f6d1d86122bc0dcf2aac6af1cc7cbb11d91046020000
```

Note that the `asm` value of the output starts with a 1, and is followed by the public key we derived above (a5ba...). The 1 means "segwit version 1" (taproot/tapscript). Since the output has the whole pubkey, not just the pubkey hash, we will actually not provide the public key when signing anymore. More on that later.

## Taproot spend

It is now possible to do a direct taproot spend using the internal privkey, and our tweak. We will use testmempoolaccept for this one, as it's too boring to waste an entire UTXO on.

First, we need to create a transaction that spends from these inputs.

```Bash
$ bcli getnewaddress
sb1qsnd43pgh7ef5rv839xc2rlpcetajq9gsjx9xcz
$ bcli createrawtransaction '[{"txid":"d4dcac1d176516dd614beef10eb7b22a666a69efcd3470b91423eca82e50f25e", "vout":0}]' '[{"sb1qsnd43pgh7ef5rv839xc2rlpcetajq9gsjx9xcz":0.0009}]'
02000000015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb20151000000000
$ tx=02000000015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb20151000000000
```

Note that we stored the resulting transaction in `tx`.

Now we can use the `tap` utility to examine and finish our transaction.

```Bash
$ tap --tx=$tx --txin=$txin $pubkey 2 $script_alice $script_bob
tap 0.2.19 -- type `tap -h` for help
WARNING: This is experimental software. Do not use this with real bitcoin, or you will most likely lose them all. You have been w a r n e d.
LOG: sign segwit taproot
targeting transaction vin at index #0
Internal pubkey: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
- no spend arguments; TAPROOT mode
2 scripts:
- #0: 029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac
- #1: a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
Script #0 leaf hash = TapLeaf<<0xc0 || 029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac>>
 → c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
Script #1 leaf hash = TapLeaf<<0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac>>
 → 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce943b42
Branch (#0, #1)
 → 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b
Tweak value = 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f1352607a9
Tweaked pubkey = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951 (not negated)
Pubkey matches the scriptPubKey of the input transaction's output #0
Resulting Bech32 address: sb1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsy7hxn9
input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d4dcac1d17, 0)
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
sighash (little endian) = e2b57cf165b3bbbb456d1d0fab7b16d131dd13598c492a41c0ff4a057c71d4dc
NOTE: there is a placeholder signature at the end of the witness data for the resulting transaction below; this must be replaced with a 64 byte signature for the sighash given above
Resulting transaction: 020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb2015100140000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00000000
```

Worth noting:
* it confirms that the pubkey matches the scriptPubKey of the input transaction's output. If this check fails, you are probably trying to spend the wrong input transaction, or index.
* it notes that the sighash is a 'taproot' sighash; if this fails with UNKNOWN sighash, it means tap was not able to determine what kind of spend this was
* there is a sighash `e2b57c...` expressed in little endian (Bitcoin Core would reverse this value when displaying); having this value means we can use a separate tool (e.g. btcdeb) to generate a signature without trusting the `tap` utility
* since we did not provide a signature or a private key, `tap` added a placeholder signature to the transaction (0001020304... 64 bytes worth). We would replace that with our actual signature, if we signed this manually.

There are 3 ways to complete this transaction: manually, by providing a signature to `tap`, or by providing the internal private key to `tap`.

* The manual approach was described above.
* To provide a signature, generate it (e.g. `tf sign <sighash> <privkey>` in btcdeb), and then pass it to `tap` via the `--sig=<hex>` argument.
* To have `tap` sign directly, hand it the private key using the `--privkey=<key>` argument (this can be a WIF string, or a hex encoded private key).

We will do the third alternative here.

```Bash
$ tap --privkey=$privkey --tx=$tx --txin=$txin $pubkey 2 $script_alice $script_bob
[...]
Resulting Bech32 address: sb1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsy7hxn9
tweaked privkey -> 4fe6b3e5fbd61870577980ad5e4e13080776069f0fb3c1e353572e0c4993abc1
The given private key matches the tweaked public key
input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d4dcac1d17, 0)
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
sighash (little endian) = e2b57cf165b3bbbb456d1d0fab7b16d131dd13598c492a41c0ff4a057c71d4dc
signature: 83967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c753427af3ae70d2793f9c745fc7293dee4bad6a9402dd838b2568907ce9bb5faae
Resulting transaction: 020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb201510014083967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c753427af3ae70d2793f9c745fc7293dee4bad6a9402dd838b2568907ce9bb5faae00000000
```

Worth noting:
* it verifies that the given private key matches the tweaked public key; if this fails, it means `tap` was unable to derive the appropriate key from your private key, to match the one in the input
* it generates a signature 8396... and then shows a resulting transaction containing this signature; let's example that transaction, but let's not broadcast it

```Bash
$ bcli decoderawtransaction 020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb201510014083967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c753427af3ae70d2793f9c745fc7293dee4bad6a9402dd838b2568907ce9bb5faae00000000
{
  "txid": "3d1f7d299fc466a171e1dccd4ad459b477816d5089cf85609418ac437223a066",
  "hash": "e60501e10899eabdb84192a8e260b25f4805262c0b09cd369ecced2f42b47701",
  "version": 2,
  "size": 150,
  "vsize": 99,
  "weight": 396,
  "locktime": 0,
  "vin": [
    {
      "txid": "d4dcac1d176516dd614beef10eb7b22a666a69efcd3470b91423eca82e50f25e",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "83967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c753427af3ae70d2793f9c745fc7293dee4bad6a9402dd838b2568907ce9bb5faae"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.00090000,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 84db588517f65341b0f129b0a1fc38cafb201510",
        "hex": "001484db588517f65341b0f129b0a1fc38cafb201510",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "sb1qsnd43pgh7ef5rv839xc2rlpcetajq9gsjx9xcz"
        ]
      }
    }
  ]
}
```

The `txinwitness` has a single entry, which matches our signature above. That's all you do for Taproot spending (you do not provide the public key; why? because it's already in the input, as we noted earlier)!

We don't want to broadcast this transaction as we still wanna try the tapscript version, but we can ask Bitcoin Core if it *would* accept it using the `testmempoolaccept` RPC command:

```Bash
$ bcli testmempoolaccept '["020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb201510014083967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c753427af3ae70d2793f9c745fc7293dee4bad6a9402dd838b2568907ce9bb5faae00000000"]'
[
  {
    "txid": "3d1f7d299fc466a171e1dccd4ad459b477816d5089cf85609418ac437223a066",
    "allowed": true
  }
]
```

We can also run this through btcdeb to see more details on how this transaction is composed:

```Bash
$ btcdeb --txin=$txin --tx=020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb201510014083967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c753427af3ae70d2793f9c745fc7293dee4bad6a9402dd838b2568907ce9bb5faae00000000
btcdeb 0.2.19 -- type `btcdeb -h` for start up options
LOG: sign segwit taproot
got segwit transaction 3d1f7d299fc466a171e1dccd4ad459b477816d5089cf85609418ac437223a066:
CTransaction(hash=3d1f7d299f, ver=2, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(d4dcac1d17, 0), scriptSig=)
    CScriptWitness(83967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c753427af3ae70d2793f9c745fc7293dee4bad6a9402dd838b2568907ce9bb5faae)
    CTxOut(nValue=0.00090000, scriptPubKey=001484db588517f65341b0f129b0a1)

got input tx #0 d4dcac1d176516dd614beef10eb7b22a666a69efcd3470b91423eca82e50f25e:
CTransaction(hash=d4dcac1d17, ver=2, vin.size=1, vout.size=2, nLockTime=582)
    CTxIn(COutPoint(d4461a7d5d, 1), scriptSig=, nSequence=4294967294)
    CScriptWitness(304402202f11adb63ae0563d6cbb1955421c7081ac559319b924f1519b3e35b334c8721b02207436ed5d3b9490c7796ee4d4fe2a90f8697c49fb4b4a8531e9446a658cef2c7d01, 023f9b34f7749620702e1ade7d8f29f6d1d86122bc0dcf2aac6af1cc7cbb11d910)
    CTxOut(nValue=0.00100000, scriptPubKey=5120a5ba0871796eb49fb4caa6bf78)
    CTxOut(nValue=49.99579079, scriptPubKey=0014068d953d034da27b8affddb1e6)

input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d4dcac1d17, 0)
2 op script loaded. type `help` for usage information
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951 | 83967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c7...
OP_CHECKSIG                                                      |
#0000 a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
btcdeb>
```

We get roughly the same output as with `tap`. Here we end up in a debugger where we can step through the script. It should be noted here that btcdeb generates a wrapping script around Taproot spends, because Taproot spends *do not have a script at all*, they simply provide a signature, the signature is verified, and that's it. Let's step twice to trigger the sig checking:

```Bash
btcdeb> step
		<> PUSH stack a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                      |   a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
                                                                 | 83967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c7...
#0001 OP_CHECKSIG
btcdeb>
GenericTransactionSignatureChecker::CheckSigSchnorr(64 len sig, 32 len pubkey, sigversion=2)
  sig         = 83967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c753427af3ae70d2793f9c745fc7293dee4bad6a9402dd838b2568907ce9bb5faae
  pub key     = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
- schnorr sighash = dcd4717c054affc0412a498c5913dd31d1167bab0f1d6d45bbbbb365f17cb5e2
  pubkey.VerifySchnorrSignature(sig=83967478a471f7f0947d1bfa4eb23280fffe827456e05e9a62e8bc81b4704c753427af3ae70d2793f9c745fc7293dee4bad6a9402dd838b2568907ce9bb5faae, sighash=dcd4717c054affc0412a498c5913dd31d1167bab0f1d6d45bbbbb365f17cb5e2):
  result: success
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
                                                                 |                                                                 01
btcdeb>
```

Signature verification succeeded. You may want to compare the values to those given by `tap` earlier, such as the sighash (which is here given Bitcoin Core style, i.e. big endian).

That concludes Taproot spending. Now for the (arguably more fun) Tapscript spending!

## Tapscript spend

Finally, we will now go and actually spend the transaction using one of our two scripts (since we don't wanna wait a day, we will go with the latter one, Bob's). To remind you, Bob's variant was:

```
OP_SHA256
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_EQUALVERIFY
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
OP_CHECKSIG
```

We need:
* The preimage, which when sha256-hashed, results in the preimage hash `6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333` as seen in the script. Luckily we made that so we've got it: `107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f`
* Bob's private key. We have that one too: `81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9`.
* The tagged hash for Alice's script, which we need to construct the merkle proof that our script above was actually a part of the deal when we both signed up for this. We got this one, since we know Alice's script beforehand, and we calculated it earlier to be `c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9`, the result of `tf tagged-hash TapLeaf c0 prefix_compact_size(029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac)` in btcdeb.
* The internal pubkey; we have this one: 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5; both Alice and Bob know it; note that we don't necessarily know the private key, since this was probably generated using MuSig or something, and requires all participants.

When doing a tapscript spend, a control object is needed, which proves that the script we are spending is actually a part of the input. We also need to actually reveal the script we chose (index starts at 0, so second script has index 1). The `tap` utility does this for us -- all we have to do is select the script we want to spend, and provide the parameters for it.

There's a lot of output so I am splitting it into a few sections:

```Bash
$ tap --tx=$tx --txin=$txin $pubkey 2 $script_alice $script_bob 1
[..]
Internal pubkey: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
1 spending argument present
- 1+ spend arguments; TAPSCRIPT mode
[..]
2 scripts:
- #0: 029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac
- #1: a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
Script #0 leaf hash = TapLeaf<<0xc0 || 029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac>>
 → c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
Script #1 leaf hash = TapLeaf<<0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac>>
 → 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce943b42
Branch (#0, #1)
 → 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b
Control object = (leaf), (internal pubkey = f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c), ...
... with proof -> f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
Tweak value = 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f1352607a9
Tweaked pubkey = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951 (not negated)
Pubkey matches the scriptPubKey of the input transaction's output #0
Resulting Bech32 address: sb1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsy7hxn9
Final control object = c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
```

Above we see a control object being generated. The first byte (`c0`) is the leaf + pubkey negation value; the leaf is simply a version, that must be `c0`. If the pubkey was negated earlier, it would be incremented by 1, to `c1`. The following 32 bytes (64 characters) match our internal public key. Can you spot where the last 32 bytes -- `c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9` -- are coming from? They are actually the alice script leaf hash! By providing this, the verifier is able to reconstruct the root and verify that our script is a part of the commitment. Read up on Merkle trees if you're confused.

```Bash
Adding selected script to taproot inputs: a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
 → 45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
Tapscript spending witness: [
 "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
 "a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac",
 "c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9",
]
```

Further down we end up with a spending witness with 3 values in it:
* the first one is a placeholder signature (it counts from 0x00 to 0x0f 4 times)
* the second one is Bob's script
* the third one is the control object that we discussed earlier

```Bash
input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 3
34 bytes (v0=P2WSH, v1=taproot/tapscript)
Verifying taproot commitment:
- control  = c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
- program  = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
- script   = a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
- path len = 1
- p        = f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
- q        = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
- k        = 423b94cec6e38364eda58e7825e582cb8ef75c13236e4191629cf2b432862c63          (tap leaf hash)
  (TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac))
- looping over path (0..0)
  - 0: node_begin = -1967116351; taproot control node match -> k first
  (TapBranch(TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac) || Span<33,32>=c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9))
  - 0: k -> 6b9f0cd659a5c64f4f5ac4f84e7998dae7fec41b47f5d7da6da9e21f8c6f6441
- final k  = a9072635f1f538909aa0f88c250acfb13c24b493580efa3f7539a50b00c40f62
  (TapTweak(internal_pubkey=f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c || TapBranch(TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac) || Span<33,32>=c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9)))
- q.CheckPayToContract(p, k, 0) == success
```

The next part is where the tapscript commitment is verified. You are encouraged to compare that `p` is our internal pubkey, `q` is the tweaked pubkey, `k` is the *reversed* hash for Bob's script, the second derivation of `k` (`6b9f0cd...`) is the *reversed* hash for the TapBranch we got earlier, and that the final k, i.e. `a907...` is the *reversed* hash of our tweak, 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f1352607a9.

The last line above is a check that the things we just verified are valid, i.e. that the script is properly committed to, in the input.

```Bash
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d4dcac1d17, 0)
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
sighash (little endian) = a9bbd0e44dc94093e8693cff53acf7306d2d1fbb812ffe718fc65857a0876e9d
NOTE: there is a placeholder signature at the end of the witness data for the resulting transaction below; this must be replaced with a 64 byte signature for the sighash given above
Resulting transaction: 020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb2015100340000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
```

Let's see how this transaction fairs when we debug it.

```Bash
$ btcdeb --txin=$txin --tx=020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb2015100340000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
[..]
5 op script loaded. type `help` for usage information
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_SHA256                                                        | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 |
OP_EQUALVERIFY                                                   |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |
OP_CHECKSIG                                                      |
#0000 OP_SHA256
btcdeb>
```

Well, the script loads and we do see Bob's script being loaded properly. We also see our placeholder signature on the right hand side. Let's step through and see what happens.

```Bash
btcdeb> step
		<> POP  stack
		<> PUSH stack 1c4672a4c6713bcb9495abba712be251bbeff723d79f001f81e5170b1d1627a5
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 |   1c4672a4c6713bcb9495abba712be251bbeff723d79f001f81e5170b1d1627a5
OP_EQUALVERIFY                                                   |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |
OP_CHECKSIG                                                      |
#0001 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
btcdeb>
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_EQUALVERIFY                                                   |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |   1c4672a4c6713bcb9495abba712be251bbeff723d79f001f81e5170b1d1627a5
OP_CHECKSIG                                                      |
#0002 OP_EQUALVERIFY
btcdeb>
		<> POP  stack
		<> POP  stack
		<> PUSH stack
error: Script failed an OP_EQUALVERIFY operation
btcdeb>
```

Unsurprisingly, our fake signature does *not* sha256-hash to the preimage hash that Bob requires. Luckily we know what the preimage is, because we created it at the very top. Let's put that in as the first script argument to tap (after the selected script index). We also want a signature by Bob in there, so let's also provide *Bob's private key* to tap. Alternatively we could run through to the end and use the sighash to generate a signature elsewhere.

```Bash
$ tap -k81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9 --tx=$tx --txin=$txin $pubkey 2 $script_alice $script_bob 1 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
[...]
Tapscript spending witness: [
 "107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f",
 "a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac",
 "c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9",
]
```

Our preimage 1076... is the first item on the stack above. The other two are as before (the Bob script and the control object).

```Bash
[..]
signature: a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1cadd984149a5604bf61729cc24af4b7c8eda88e0aac91c241a19d1c55000f137a4
Resulting transaction: 020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb2015100440a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1cadd984149a5604bf61729cc24af4b7c8eda88e0aac91c241a19d1c55000f137a420107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
```

This time we get a real signature (a9e7..) and a resulting transaction. Let's run that transaction through btcdeb first of all:

```Bash
$ btcdeb --txin=$txin --tx=020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb2015100440a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1cadd984149a5604bf61729cc24af4b7c8eda88e0aac91c241a19d1c55000f137a420107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
[...]
5 op script loaded. type `help` for usage information
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_SHA256                                                        |   107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 | a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1c...
OP_EQUALVERIFY                                                   |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |
OP_CHECKSIG                                                      |
#0000 OP_SHA256
btcdeb>
```

This looks better! Let's see how it fares:

```Bash
btcdeb> step
		<> POP  stack
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_EQUALVERIFY                                                   | a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1c...
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |
OP_CHECKSIG                                                      |
#0001 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
btcdeb>
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_EQUALVERIFY                                                   |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_CHECKSIG                                                      | a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1c...
#0002 OP_EQUALVERIFY
btcdeb>
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
		<> POP  stack
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 | a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1c...
OP_CHECKSIG                                                      |
#0003 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
btcdeb>
		<> PUSH stack 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                      |   4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
                                                                 | a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1c...
#0004 OP_CHECKSIG
btcdeb>
Eval Checksig Tapscript
- sig must not be empty: ok
- validation weight - 50 -> 235
- 32 byte pubkey (new type); schnorr sig check
GenericTransactionSignatureChecker::CheckSigSchnorr(64 len sig, 32 len pubkey, sigversion=3)
  sig         = a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1cadd984149a5604bf61729cc24af4b7c8eda88e0aac91c241a19d1c55000f137a4
  pub key     = 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
- schnorr sighash = 9d6e87a05758c68f71fe2f81bb1f2d6d30f7ac53ff3c69e89340c94de4d0bba9
  pubkey.VerifySchnorrSignature(sig=a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1cadd984149a5604bf61729cc24af4b7c8eda88e0aac91c241a19d1c55000f137a4, sighash=9d6e87a05758c68f71fe2f81bb1f2d6d30f7ac53ff3c69e89340c94de4d0bba9):
  result: success
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
                                                                 |                                                                 01
btcdeb>
```

Yay! Let's send this transaction and see if it flies:

```Bash
$ bcli sendrawtransaction 020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb2015100440a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1cadd984149a5604bf61729cc24af4b7c8eda88e0aac91c241a19d1c55000f137a420107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
3d1f7d299fc466a171e1dccd4ad459b477816d5089cf85609418ac437223a066
$ bcli getrawtransaction 3d1f7d299fc466a171e1dccd4ad459b477816d5089cf85609418ac437223a066 1
{
  "txid": "3d1f7d299fc466a171e1dccd4ad459b477816d5089cf85609418ac437223a066",
  "hash": "a5f746e30a4c2d5f7e0802e3ede423cda2c0a66c66536312050b6d8b0cc276b8",
  "version": 2,
  "size": 319,
  "vsize": 142,
  "weight": 565,
  "locktime": 0,
  "vin": [
    {
      "txid": "d4dcac1d176516dd614beef10eb7b22a666a69efcd3470b91423eca82e50f25e",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1cadd984149a5604bf61729cc24af4b7c8eda88e0aac91c241a19d1c55000f137a4",
        "107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f",
        "a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac",
        "c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.00090000,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 84db588517f65341b0f129b0a1fc38cafb201510",
        "hex": "001484db588517f65341b0f129b0a1fc38cafb201510",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "sb1qsnd43pgh7ef5rv839xc2rlpcetajq9gsjx9xcz"
        ]
      }
    }
  ],
  "hex": "020000000001015ef2502ea8ec2314b97034cdef696a662ab2b70ef1ee4b61dd1665171dacdcd40000000000ffffffff01905f01000000000016001484db588517f65341b0f129b0a1fc38cafb2015100440a9e724f9b427816a6c902fdee8aaa1b63d22e46a434387fb2d111b6108d1b1cadd984149a5604bf61729cc24af4b7c8eda88e0aac91c241a19d1c55000f137a420107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c0f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000"
}
$
```

And we're done! Hope it was helpful. Please submit pull requests or issues with improvements to this document and/or btcdeb.

If you want to do this all manually by hand to really get your hands dirty, you can redo this exercise (with slightly different values) over [here](tapscript-example.md).
