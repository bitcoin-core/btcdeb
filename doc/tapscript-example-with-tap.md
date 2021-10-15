# Tapscript example using Tap

The taproot-new branch of btcdeb contains experimental support for the work-in-progress Taproot proposal by Pieter Wuille and others. (See https://github.com/bitcoin/bitcoin/pull/17977)

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
tap 0.2.20 -- type `tap -h` for help
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
Tweak value = TapTweak(f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c || 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b) = 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f1352607a9
Tweaked pubkey = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951 (not even)
Resulting Bech32 address: bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gswkh8l6
```

The output is quite verbose right now, but lets go through what's being said here:
* There is an internal pubkey f30...; we provided this one (`$pubkey`)
* There are 2 scripts, the alice and bob scripts
* There are *leaf hashes* for each of the scripts; we will talk about these more when we do the Tapscript spend
* There's a branch for script #0 and #1 -- this simply ties the two scripts above together into a merkle tree
* There's a tweak value, which is based on the above merkle tree, and a tweaked pubkey, which is our given pubkey *tweaked* with the above tweak. To put it simply, we are applying our scripts to our pubkey, to form a new pubkey which commits to those scripts.
* Finally, there's a Bech32 address. This is where we wanna send funds. Let's send 0.001 coins to it.

```Bash
$ alias bcli='bitcoin-cli -regtest' # change this to whatever command you use to access bitcoin-cli
$ bcli sendtoaddress bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gswkh8l6 0.001
d52f9cf3cad529baa892f15f91bb4e2b9894ec57a0b32521e6bd4d05c9dd021a
$ bcli getrawtransaction d52f9cf3cad529baa892f15f91bb4e2b9894ec57a0b32521e6bd4d05c9dd021a 1
{
  "txid": "d52f9cf3cad529baa892f15f91bb4e2b9894ec57a0b32521e6bd4d05c9dd021a",
  "hash": "19b49bb86cb4d61b52526902c9672e975a22502161a3d6ec0aa00c0c29026a23",
  "version": 2,
  "size": 234,
  "vsize": 153,
  "weight": 609,
  "locktime": 0,
  "vin": [
    {
      "txid": "052033d0fab8054fb7c3048fc4b446ba1976d84a59a95474c27e6b54ace0f7bb",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "3044022047f581cc873a6ef81bf1fadd5c55c414a8983776b387ee07e3429deffbbfe535022076af783fcaea2064a480d2a54bd727211ee0cb56ba9efeb0481c9362b86d4b5901",
        "02077c102914911f57b8c1881e207ea09297024803e1c10ce3f20453c2c3f735c6"
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
        "type": "witness_v1_taproot",
        "addresses": [
          "bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gswkh8l6"
        ]
      }
    },
    {
      "value": 49.99899847,
      "n": 1,
      "scriptPubKey": {
        "asm": "0 c3c95a40e8e5435f103224ace16c58a55758f54d",
        "hex": "0014c3c95a40e8e5435f103224ace16c58a55758f54d",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "bcrt1qc0y45s8gu4p47ypjyjkwzmzc54t43a2dgqrhpf"
        ]
      }
    }
  ],
  "hex": "02000000000101bbf7e0ac546b7ec27454a9594ad87619ba46b4c48f04c3b74f05b8fad03320050000000000feffffff02a086010000000000225120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951c76a042a01000000160014c3c95a40e8e5435f103224ace16c58a55758f54d02473044022047f581cc873a6ef81bf1fadd5c55c414a8983776b387ee07e3429deffbbfe535022076af783fcaea2064a480d2a54bd727211ee0cb56ba9efeb0481c9362b86d4b59012102077c102914911f57b8c1881e207ea09297024803e1c10ce3f20453c2c3f735c600000000"
}
```

This will be our input transaction. Make note of the index in the vout array of our output -- in this case it is index 0. We need to keep that index and that hex value around, so let's save those as environment variables:
```Bash
$ vin=0 # CONFIRM THIS OR THINGS WILL FAIL
$ txin=02000000000101bbf7e0ac546b7ec27454a9594ad87619ba46b4c48f04c3b74f05b8fad03320050000000000feffffff02a086010000000000225120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951c76a042a01000000160014c3c95a40e8e5435f103224ace16c58a55758f54d02473044022047f581cc873a6ef81bf1fadd5c55c414a8983776b387ee07e3429deffbbfe535022076af783fcaea2064a480d2a54bd727211ee0cb56ba9efeb0481c9362b86d4b59012102077c102914911f57b8c1881e207ea09297024803e1c10ce3f20453c2c3f735c600000000
```

Note that the `asm` value of the output starts with a 1, and is followed by the public key we derived above (a5ba...). The 1 means "segwit version 1" (taproot/tapscript). Since the output has the whole pubkey, not just the pubkey hash, we will actually not provide the public key when signing anymore. More on that later.

## Taproot spend

It is now possible to do a direct taproot spend using the internal privkey, and our tweak. We will use testmempoolaccept for this one, as it's too boring to waste an entire UTXO on.

First, we need to create a transaction that spends from these inputs.

```Bash
$ bcli getnewaddress
bcrt1qnuu6g4paxygkzk46dfxztm2xjzfs52lvu6twa9
$ bcli createrawtransaction '[{"txid":"d52f9cf3cad529baa892f15f91bb4e2b9894ec57a0b32521e6bd4d05c9dd021a", "vout":0}]' '[{"bcrt1qnuu6g4paxygkzk46dfxztm2xjzfs52lvu6twa9":0.0009}]'
02000000011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec00000000
$ tx=02000000011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec00000000
```

Note that we stored the resulting transaction in `tx`.

Now we can use the `tap` utility to examine and finish our transaction.

```Bash
$ tap --tx=$tx --txin=$txin $pubkey 2 $script_alice $script_bob
tap 0.2.20 -- type `tap -h` for help
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
Tweak value = TapTweak(f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c || 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b) = 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f1352607a9
Tweaked pubkey = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951 (not even)
Pubkey matches the scriptPubKey of the input transaction's output #0
Resulting Bech32 address: bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gswkh8l6
input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d52f9cf3ca, 0)
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
sighash (little endian) = b265d5b06880aba0c0c28817fb4f9959e66025a8f4620e59e6f4af0c3e610cfd
NOTE: there is a placeholder signature at the end of the witness data for the resulting transaction below; this must be replaced with a 64 byte signature for the sighash given above
Resulting transaction: 020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec0140000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00000000
```

Worth noting:
* it confirms that the pubkey matches the scriptPubKey of the input transaction's output. If this check fails, you are probably trying to spend the wrong input transaction, or index.
* it notes that the sighash is a 'taproot' sighash; if this fails with UNKNOWN sighash, it means tap was not able to determine what kind of spend this was
* there is a sighash `b265d5...` expressed in little endian (Bitcoin Core would reverse this value when displaying); having this value means we can use a separate tool (e.g. btcdeb) to generate a signature without trusting the `tap` utility
* since we did not provide a signature or a private key, `tap` added a placeholder signature to the transaction (0001020304... 64 bytes worth). We would replace that with our actual signature, if we signed this manually.

There are 3 ways to complete this transaction: manually, by providing a signature to `tap`, or by providing the internal private key to `tap`.

* The manual approach was described above.
* To provide a signature, generate it (e.g. `tf sign <sighash> <privkey>` in btcdeb), and then pass it to `tap` via the `--sig=<hex>` argument.
* To have `tap` sign directly, hand it the private key using the `--privkey=<key>` argument (this can be a WIF string, or a hex encoded private key).

We will do the third alternative here.

```Bash
$ tap --privkey=$privkey --tx=$tx --txin=$txin $pubkey 2 $script_alice $script_bob
[...]
Resulting Bech32 address: bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gswkh8l6
tweaked privkey -> 4fe6b3e5fbd61870577980ad5e4e13080776069f0fb3c1e353572e0c4993abc1
(pk_parity = 1)
The given private key matches the tweaked public key
input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d52f9cf3ca, 0)
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
sighash (little endian) = b265d5b06880aba0c0c28817fb4f9959e66025a8f4620e59e6f4af0c3e610cfd
sighash: b265d5b06880aba0c0c28817fb4f9959e66025a8f4620e59e6f4af0c3e610cfd
privkey: 4fe6b3e5fbd61870577980ad5e4e13080776069f0fb3c1e353572e0c4993abc1
pubkey: a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
signature: 22195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fdf97a7ba15c211e4f1773948f2fa25f066b6b7c174b41a83e21f50f13a99235f82
Resulting transaction: 020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec014022195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fdf97a7ba15c211e4f1773948f2fa25f066b6b7c174b41a83e21f50f13a99235f8200000000
```

Worth noting:
* it verifies that the given private key matches the tweaked public key; if this fails, it means `tap` was unable to derive the appropriate key from your private key, to match the one in the input
* it generates a signature 8396... and then shows a resulting transaction containing this signature; let's examine that transaction, but let's not broadcast it

```Bash
$ bcli decoderawtransaction 020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec014022195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fdf97a7ba15c211e4f1773948f2fa25f066b6b7c174b41a83e21f50f13a99235f8200000000
{
  "txid": "151156e7c0d80475492a4ff692e2d7e2e226478b166fe7a588943474fb75c1b1",
  "hash": "fe4a2271d125d10ee681b9560efd00abc9ef3b14d1acb9a162dfaef3dffa51ba",
  "version": 2,
  "size": 150,
  "vsize": 99,
  "weight": 396,
  "locktime": 0,
  "vin": [
    {
      "txid": "d52f9cf3cad529baa892f15f91bb4e2b9894ec57a0b32521e6bd4d05c9dd021a",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "22195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fdf97a7ba15c211e4f1773948f2fa25f066b6b7c174b41a83e21f50f13a99235f82"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.00090000,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 9f39a4543d3111615aba6a4c25ed4690930a2bec",
        "hex": "00149f39a4543d3111615aba6a4c25ed4690930a2bec",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "bcrt1qnuu6g4paxygkzk46dfxztm2xjzfs52lvu6twa9"
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
$ btcdeb --txin=$txin --tx=020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec014022195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fdf97a7ba15c211e4f1773948f2fa25f066b6b7c174b41a83e21f50f13a99235f8200000000
btcdeb 0.2.20 -- type `./btcdeb -h` for start up options
LOG: sign segwit taproot
got segwit transaction 151156e7c0d80475492a4ff692e2d7e2e226478b166fe7a588943474fb75c1b1:
CTransaction(hash=151156e7c0, ver=2, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(d52f9cf3ca, 0), scriptSig=)
    CScriptWitness(22195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fdf97a7ba15c211e4f1773948f2fa25f066b6b7c174b41a83e21f50f13a99235f82)
    CTxOut(nValue=0.00090000, scriptPubKey=00149f39a4543d3111615aba6a4c25)

got input tx #0 d52f9cf3cad529baa892f15f91bb4e2b9894ec57a0b32521e6bd4d05c9dd021a:
CTransaction(hash=d52f9cf3ca, ver=2, vin.size=1, vout.size=2, nLockTime=0)
    CTxIn(COutPoint(052033d0fa, 0), scriptSig=, nSequence=4294967294)
    CScriptWitness(3044022047f581cc873a6ef81bf1fadd5c55c414a8983776b387ee07e3429deffbbfe535022076af783fcaea2064a480d2a54bd727211ee0cb56ba9efeb0481c9362b86d4b5901, 02077c102914911f57b8c1881e207ea09297024803e1c10ce3f20453c2c3f735c6)
    CTxOut(nValue=0.00100000, scriptPubKey=5120a5ba0871796eb49fb4caa6bf78)
    CTxOut(nValue=49.99899847, scriptPubKey=0014c3c95a40e8e5435f103224ace1)

input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d52f9cf3ca, 0)
2 op script loaded. type `help` for usage information
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951 | 22195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fd...
OP_CHECKSIG                                                      |
#0000 a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
btcdeb> step
		<> PUSH stack a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                      |   a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
                                                                 | 22195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fd...
#0001 OP_CHECKSIG
btcdeb>
EvalChecksig() sigversion=2
GenericTransactionSignatureChecker::CheckSchnorrSignature(64 len sig, 32 len pubkey, sigversion=2)
  sig         = 22195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fdf97a7ba15c211e4f1773948f2fa25f066b6b7c174b41a83e21f50f13a99235f82
  pub key     = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
- schnorr sighash = fd0c613e0caff4e6590e62f4a82560e659994ffb1788c2c0a0ab8068b0d565b2
  pubkey.VerifySchnorrSignature(sig=22195d2c3e02466e4feeb1196e7c30d931883b505d60ea00126b12923d302fdf97a7ba15c211e4f1773948f2fa25f066b6b7c174b41a83e21f50f13a99235f82, sighash=fd0c613e0caff4e6590e62f4a82560e659994ffb1788c2c0a0ab8068b0d565b2):
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
* The internal pubkey; we have this one: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c; both Alice and Bob know it; note that we don't necessarily know the private key, since this was probably generated using MuSig or something, and requires all participants.

When doing a tapscript spend, a control object is needed, which proves that the script we are spending is actually a part of the input. We also need to actually reveal the script we chose (index starts at 0, so second script has index 1). The `tap` utility does this for us -- all we have to do is select the script we want to spend, and provide the parameters for it.

There's a lot of output so I am splitting it into a few sections:

```Bash
$ tap --tx=$tx --txin=$txin $pubkey 2 $script_alice $script_bob 1
[..]
Internal pubkey: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
1 spending argument present
- 1+ spend arguments; TAPSCRIPT mode
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
Tweak value = TapTweak(f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c || 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b) = 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f1352607a9
Tweaked pubkey = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951 (not even)
Pubkey matches the scriptPubKey of the input transaction's output #0
Resulting Bech32 address: bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gswkh8l6
Final control object = c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
```

Above we see a control object being generated. The first byte (`c1`) is the leaf + pubkey parity bit; the leaf is simply a version, that must be `c0`. If the pubkey turned out to be uneven earlier, so the version is incremented by 1 (the parity bit), to `c1`. The following 32 bytes (64 characters) match our internal public key. Can you spot where the last 32 bytes -- `c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9` -- are coming from? They are actually the alice script leaf hash! By providing this, the verifier is able to reconstruct the root and verify that our script is a part of the commitment. Read up on Merkle trees if you're confused.

```Bash
Adding selected script to taproot inputs: a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
 → 45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
appending control object to taproot input stack: c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
Tapscript spending witness: [
 "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
 "a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac",
 "c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9",
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
Taproot commitment:
- control  = c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
- program  = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
- script   = a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
- path len = 1
- p        = f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
- q        = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
- k        = 423b94cec6e38364eda58e7825e582cb8ef75c13236e4191629cf2b432862c63          (tap leaf hash)
  (TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac))
```

The next part is where the tapscript commitment is verified. You are encouraged to compare that `p` is our internal pubkey, `q` is the tweaked pubkey, `k` is the *reversed* hash for Bob's script


<!-- , the second derivation of `k` (`6b9f0cd...`) is the *reversed* hash for the TapBranch we got earlier, and that the final k, i.e. `a907...` is the *reversed* hash of our tweak, 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f1352607a9.

The last line above is a check that the things we just verified are valid, i.e. that the script is properly committed to, in the input. -->

```Bash
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d52f9cf3ca, 0)
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
sighash (little endian) = 6c424fc82353e9231590b43e24337b2e07e00dee10ee12bc0af8905f0a0fee62
NOTE: there is a placeholder signature at the end of the witness data for the resulting transaction below; this must be replaced with a 64 byte signature for the sighash given above
Resulting transaction: 020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec0340000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
```

Let's see how this transaction fairs when we debug it.

```Bash
$ btcdeb --txin=$txin --tx=020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec0340000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
[..]
9 op script loaded. type `help` for usage information
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
<<< taproot commitment >>>                                         |                                                               i: 0
Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205f... | k: 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce94...
Tweak: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5... |
CheckPayToContract                                                 |
<<< committed script >>>                                           |
OP_SHA256                                                          |
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   |
OP_EQUALVERIFY                                                     |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0000 Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
```

The script starts up with the taproot commitment part. We also see that Bob's script is shown. The right hand side is currently showing the index (`i`) and `k` value of the taproot commitment. Let's step through and see how the taproot commitment is validated:

Note: `k` starts out as `632c8632...` which is equal to the Script #1 leaf hash, `TapLeaf<<0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac>>` which equals `632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce943b42`.

```Bash
btcdeb> step
- looping over path (0..0)
  - 0: node = c8...; taproot control node match -> k first
  (TapBranch(TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac) || Span<33,32>=c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9))
  - 0: k -> 6b9f0cd659a5c64f4f5ac4f84e7998dae7fec41b47f5d7da6da9e21f8c6f6441
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
<<< taproot commitment >>>                                         |                                                               i: 1
Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205f... | k: 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c...
Tweak: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5... |
CheckPayToContract                                                 |
<<< committed script >>>                                           |
OP_SHA256                                                          |
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   |
OP_EQUALVERIFY                                                     |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0001 Tweak: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
```

After one iteration (`i → 1`), we end up with `k` equal to the branch (#0, #1) value (which you can confirm by scrolling up).

We step again, to reveal the final `k` value:
```Bash
btcdeb> step
- looping over path (0..0)
- final k  = a9072635f1f538909aa0f88c250acfb13c24b493580efa3f7539a50b00c40f62
  (TapTweak(internal_pubkey=f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c || TapBranch(TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac) || Span<33,32>=c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9)))
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
<<< taproot commitment >>>                                         |                                                               i: 1
Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205f... | k: 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f13526...
Tweak: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5... |
CheckPayToContract                                                 |
<<< committed script >>>                                           |
OP_SHA256                                                          |
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   |
OP_EQUALVERIFY                                                     |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0002 CheckPayToContract
```

The new `k` (`620fc40`) is the tweak value, i.e. `TapTweak(internal pubkey || k) = 620fc4000ba539753ffa0e5893b4243cb1cf0a258cf8a09a9038f5f1352607a9`, also derived previously; i.e. we've now added the internal key to the resulting final `k`.

```Bash
btcdeb> step
- looping over path (0..0)
- q.CheckPayToContract(p, k, 1) == success
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_SHA256                                                          | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   |
OP_EQUALVERIFY                                                     |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0003 OP_SHA256
```

The next step is calling the `CheckPayToContract()` method in the public key class, which takes the internal pubkey `p` and tweak+internal pubkey `k` and ensures that the tweaked pubkey `q` satisfies `tweak(p, k) = q`, where `tweak()` is defined as in BIP340-342. (The third argument, 1, is the parity bit.)

At this point we have Bob's script loaded up, and the tapscript commitment phase is complete. From here on, it's just like the good old usual. This won't work, of course, but let's see what happens when we step through:

```Bash
btcdeb> step
		<> POP  stack
		<> PUSH stack 1c4672a4c6713bcb9495abba712be251bbeff723d79f001f81e5170b1d1627a5
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   |   1c4672a4c6713bcb9495abba712be251bbeff723d79f001f81e5170b1d1627a5
OP_EQUALVERIFY                                                     |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0004 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
btcdeb>
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_EQUALVERIFY                                                     |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |   1c4672a4c6713bcb9495abba712be251bbeff723d79f001f81e5170b1d1627a5
OP_CHECKSIG                                                        |
#0005 OP_EQUALVERIFY
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
 "c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9",
]
```

Our preimage 1076... is the first item on the stack above. The other two are as before (the Bob script and the control object).

```Bash
[..]
signature: 4d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f36a8ff35ffffe95ef35450466fafd13f6ee2343373cd8785712657e57f51168e87
Resulting transaction: 020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec04404d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f36a8ff35ffffe95ef35450466fafd13f6ee2343373cd8785712657e57f51168e8720107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
```

This time we get a real signature (4d0e..) and a resulting transaction. Let's run that transaction through btcdeb first of all (step through the taproot commitment stuff until we get to Bob's script):

```Bash
$ btcdeb --txin=$txin --tx=020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec04404d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f36a8ff35ffffe95ef35450466fafd13f6ee2343373cd8785712657e57f51168e8720107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
[...]
btcdeb> step
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_SHA256                                                          |   107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   | 4d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f3...
OP_EQUALVERIFY                                                     |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0003 OP_SHA256
btcdeb>
```

This looks better! Let's see how it fares:

```Bash
btcdeb> step
		<> POP  stack
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_EQUALVERIFY                                                     | 4d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f3...
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0004 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
btcdeb>
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_EQUALVERIFY                                                     |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_CHECKSIG                                                        | 4d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f3...
#0005 OP_EQUALVERIFY
btcdeb>
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
		<> POP  stack
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   | 4d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f3...
OP_CHECKSIG                                                        |
#0006 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
btcdeb>
		<> PUSH stack 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                        |   4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
                                                                   | 4d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f3...
#0007 OP_CHECKSIG
btcdeb>
EvalChecksig() sigversion=3
Eval Checksig Tapscript
- sig must not be empty: ok
- validation weight - 50 -> 235
- 32 byte pubkey (new type); schnorr sig check
GenericTransactionSignatureChecker::CheckSchnorrSignature(64 len sig, 32 len pubkey, sigversion=3)
  sig         = 4d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f36a8ff35ffffe95ef35450466fafd13f6ee2343373cd8785712657e57f51168e87
  pub key     = 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
- schnorr sighash = 62ee0f0a5f90f80abc12ee10ee0de0072e7b33243eb4901523e95323c84f426c
  pubkey.VerifySchnorrSignature(sig=4d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f36a8ff35ffffe95ef35450466fafd13f6ee2343373cd8785712657e57f51168e87, sighash=62ee0f0a5f90f80abc12ee10ee0de0072e7b33243eb4901523e95323c84f426c):
  result: success
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
                                                                   |                                                                 01
btcdeb>
```

Yay! Let's send this transaction and see if it flies:

```Bash
$ bcli sendrawtransaction 020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec04404d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f36a8ff35ffffe95ef35450466fafd13f6ee2343373cd8785712657e57f51168e8720107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
151156e7c0d80475492a4ff692e2d7e2e226478b166fe7a588943474fb75c1b1
$ bcli getrawtransaction 151156e7c0d80475492a4ff692e2d7e2e226478b166fe7a588943474fb75c1b1 1
{
  "txid": "151156e7c0d80475492a4ff692e2d7e2e226478b166fe7a588943474fb75c1b1",
  "hash": "6f8089660ffd0cea4ea20f017bb46c0f571d282e49325468076dc70aa91bda55",
  "version": 2,
  "size": 319,
  "vsize": 142,
  "weight": 565,
  "locktime": 0,
  "vin": [
    {
      "txid": "d52f9cf3cad529baa892f15f91bb4e2b9894ec57a0b32521e6bd4d05c9dd021a",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "4d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f36a8ff35ffffe95ef35450466fafd13f6ee2343373cd8785712657e57f51168e87",
        "107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f",
        "a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac",
        "c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.00090000,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 9f39a4543d3111615aba6a4c25ed4690930a2bec",
        "hex": "00149f39a4543d3111615aba6a4c25ed4690930a2bec",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "bcrt1qnuu6g4paxygkzk46dfxztm2xjzfs52lvu6twa9"
        ]
      }
    }
  ],
  "hex": "020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec04404d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f36a8ff35ffffe95ef35450466fafd13f6ee2343373cd8785712657e57f51168e8720107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000"
}
$
```

And we're done! Hope it was helpful. Please submit pull requests or issues with improvements to this document and/or btcdeb.

If you want to do this all manually by hand to really get your hands dirty, you can redo this exercise (with slightly different values) over [here](tapscript-example.md).
