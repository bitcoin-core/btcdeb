# Tapscript example using Tap

This document describes one process with which you can create, from scratch, your own Tapscript output, fund it, and then spend one of its paths.

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
$ tap $pubkey 2 "${script_alice}" "${script_bob}"
tap 0.4.22 -- type `tap -h` for help
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
Resulting Bech32m address: bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsm28t6c
```

The output is quite verbose right now, but lets go through what's being said here:
* There is an internal pubkey f30...; we provided this one (`$pubkey`)
* There are 2 scripts, the alice and bob scripts
* There are *leaf hashes* for each of the scripts; we will talk about these more when we do the Tapscript spend
* There's a branch for script #0 and #1 -- this simply ties the two scripts above together into a merkle tree
* There's a tweak value, which is based on the above merkle tree, and a tweaked pubkey, which is our given pubkey *tweaked* with the above tweak. To put it simply, we are applying our scripts to our pubkey, to form a new pubkey which commits to those scripts.
* Finally, there's a Bech32m address. This is where we wanna send funds. Let's send 0.001 coins to it.

```Bash
$ alias bcli='bitcoin-cli -regtest' # change this to whatever command you use to access bitcoin-cli
$ bcli sendtoaddress bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsm28t6c 0.001
ec409014a3b1e7171cf498726bc7bc8bd249a04b65f30c7b8cb5c3079cf8f271
$ bcli getrawtransaction ec409014a3b1e7171cf498726bc7bc8bd249a04b65f30c7b8cb5c3079cf8f271 1
{
  "txid": "ec409014a3b1e7171cf498726bc7bc8bd249a04b65f30c7b8cb5c3079cf8f271",
  "hash": "c2c9b5d2b122e0765ca4200c58a2c0bb2d87da17c4299b41aa03f4ee650e06e4",
  "version": 2,
  "size": 234,
  "vsize": 153,
  "weight": 609,
  "locktime": 0,
  "vin": [
    {
      "txid": "c26f6c2d404ae1228dd7d53a37e70b87e546f7138fc88efc800c208f8733a60a",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "3044022017de23798d7a01946744421fbb79a48556da809a9ffdb729f6e5983051480991022052460a5082749422804ad2a25e6f8335d5cf31f69799cece4a1ccc0256d5010701",
        "0257e0052b0ec6736ee13392940b7932571ce91659f71e899210b8daaf6f170275"
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
        "address": "bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsm28t6c",
        "type": "witness_v1_taproot"
      }
    },
    {
      "value": 0.99899847,
      "n": 1,
      "scriptPubKey": {
        "asm": "0 7bf84e78c81b9fed7a47b9251d95b13d6ebac141",
        "hex": "00147bf84e78c81b9fed7a47b9251d95b13d6ebac141",
        "address": "bcrt1q00uyu7xgrw0767j8hyj3m9d384ht4s2p3058pr",
        "type": "witness_v0_keyhash"
      }
    }
  ],
  "hex": "020000000001010aa633878f200c80fc8ec88f13f746e5870be7373ad5d78d22e14a402d6c6fc20000000000feffffff02a086010000000000225120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951c759f405000000001600147bf84e78c81b9fed7a47b9251d95b13d6ebac14102473044022017de23798d7a01946744421fbb79a48556da809a9ffdb729f6e5983051480991022052460a5082749422804ad2a25e6f8335d5cf31f69799cece4a1ccc0256d5010701210257e0052b0ec6736ee13392940b7932571ce91659f71e899210b8daaf6f17027500000000"
}
```

This will be our input transaction. Make note of the index in the vout array of our output -- in this case it is index 0. We need to keep that index and that hex value around, so let's save those as environment variables:
```Bash
$ vout=0 # CONFIRM THIS OR THINGS WILL FAIL
$ txin=020000000001010aa633878f200c80fc8ec88f13f746e5870be7373ad5d78d22e14a402d6c6fc20000000000feffffff02a086010000000000225120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951c759f405000000001600147bf84e78c81b9fed7a47b9251d95b13d6ebac14102473044022017de23798d7a01946744421fbb79a48556da809a9ffdb729f6e5983051480991022052460a5082749422804ad2a25e6f8335d5cf31f69799cece4a1ccc0256d5010701210257e0052b0ec6736ee13392940b7932571ce91659f71e899210b8daaf6f17027500000000
```

Note that the `asm` value of the output starts with a 1, and is followed by the public key we derived above (a5ba...). The 1 means "segwit version 1" (taproot/tapscript). Since the output has the whole pubkey, not just the pubkey hash, we will actually not provide the public key when signing anymore. More on that later.

## Taproot spend

It is now possible to do a direct taproot spend using the internal privkey, and our tweak. We will use testmempoolaccept for this one, as it's too boring to waste an entire UTXO on.

First, we need to create a transaction that spends from these inputs.

```Bash
$ bcli getnewaddress
bcrt1qe6ed9zhaetg6ur7ze7quhy5m520gx35znudxan
$ tx=$(bcli createrawtransaction '[{"txid":"ec409014a3b1e7171cf498726bc7bc8bd249a04b65f30c7b8cb5c3079cf8f271", "vout":$vout}]' '[{"bcrt1qe6ed9zhaetg6ur7ze7quhy5m520gx35znudxan":0.0009}]')
$ echo $tx
020000000171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e83468200000000
```

Note that we stored the resulting transaction in `tx`.

Now we can use the `tap` utility to examine and finish our transaction.

```Bash
$ tap --tx=$tx --txin=$txin $pubkey 2 "${script_alice}" "${script_bob}"
tap 0.4.22 -- type `tap -h` for help
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
Resulting Bech32m address: bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsm28t6c
input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(ec409014a3, 0)
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
sighash (little endian) = 28e88d197adeaf164a96b68965907ded7e41d6945ee720b1480724499fdf102d
NOTE: there is a placeholder signature at the end of the witness data for the resulting transaction below; this must be replaced with a 64 byte signature for the sighash given above
Resulting transaction: 0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e8346820140000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00000000
```

Worth noting:
* it confirms that the pubkey matches the scriptPubKey of the input transaction's output. If this check fails, you are probably trying to spend the wrong input transaction, or index.
* it notes that the sighash is a 'taproot' sighash; if this fails with UNKNOWN sighash, it means tap was not able to determine what kind of spend this was
* there is a sighash `28e88d1...` expressed in little endian (Bitcoin Core would reverse this value when displaying); having this value means we can use a separate tool (e.g. btcdeb) to generate a signature without trusting the `tap` utility
* since we did not provide a signature or a private key, `tap` added a placeholder signature to the transaction (0001020304... 64 bytes worth). We would replace that with our actual signature, if we signed this manually.

There are 3 ways to complete this transaction: (1) manually, (2) by providing a signature to `tap`, or (3) by providing the internal private key to `tap`.

* The manual approach was described above.
* To provide a signature, generate it (e.g. `tf sign_schnorr <sighash> <privkey>` in btcdeb), and then pass it to `tap` via the `--sig=<hex>` argument.
* To have `tap` sign directly, hand it the private key using the `--privkey=<key>` argument (this can be a WIF string, or a hex encoded private key).

We will do the third alternative here.

```Bash
$ tap --privkey=$privkey --tx=$tx --txin=$txin $pubkey 2 "${script_alice}" "${script_bob}"
[...]
Resulting Bech32m address: bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsm28t6c
tweaked privkey -> 4fe6b3e5fbd61870577980ad5e4e13080776069f0fb3c1e353572e0c4993abc1
(pk_parity = 1)
The given private key matches the tweaked public key
input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(ec409014a3, 0)
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
sighash (little endian) = 28e88d197adeaf164a96b68965907ded7e41d6945ee720b1480724499fdf102d
sighash: 28e88d197adeaf164a96b68965907ded7e41d6945ee720b1480724499fdf102d
privkey: 4fe6b3e5fbd61870577980ad5e4e13080776069f0fb3c1e353572e0c4993abc1
pubkey: a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
signature: 742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d6a9e304e069d07bc60fc351dff7e5599b11309731b4dc5eea4f5fd6560dec0be2
Resulting transaction: 0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e8346820140742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d6a9e304e069d07bc60fc351dff7e5599b11309731b4dc5eea4f5fd6560dec0be200000000
```

Worth noting:
* it verifies that the given private key matches the tweaked public key; if this fails, it means `tap` was unable to derive the appropriate key from your private key, to match the one in the input
* it generates a signature 742c... and then shows a resulting transaction containing this signature; let's examine that transaction, but let's not broadcast it

```Bash
$ bcli decoderawtransaction 0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e8346820140742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d6a9e304e069d07bc60fc351dff7e5599b11309731b4dc5eea4f5fd6560dec0be200000000
{
  "txid": "068f9bc8ce2312568dc78a779b8231555e6f05fb170dbbe9a6a30d51048d5580",
  "hash": "69d0ad20a1bbdc76521fe9f41518bfbb91cd1e215b5854e50d2b8d123f277acc",
  "version": 2,
  "size": 150,
  "vsize": 99,
  "weight": 396,
  "locktime": 0,
  "vin": [
    {
      "txid": "ec409014a3b1e7171cf498726bc7bc8bd249a04b65f30c7b8cb5c3079cf8f271",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d6a9e304e069d07bc60fc351dff7e5599b11309731b4dc5eea4f5fd6560dec0be2"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.00090000,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 ceb2d28afdcad1ae0fc2cf81cb929ba29e834682",
        "hex": "0014ceb2d28afdcad1ae0fc2cf81cb929ba29e834682",
        "address": "bcrt1qe6ed9zhaetg6ur7ze7quhy5m520gx35znudxan",
        "type": "witness_v0_keyhash"
      }
    }
  ]
}
```

The `txinwitness` has a single entry, which matches our signature above. That's all you do for Taproot spending (you do not provide the public key; why? because it's already in the input, as we noted earlier)!

We don't want to broadcast this transaction as we still wanna try the tapscript version, but we can ask Bitcoin Core if it *would* accept it using the `testmempoolaccept` RPC command:

```Bash
$ bcli testmempoolaccept '["0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e8346820140742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d6a9e304e069d07bc60fc351dff7e5599b11309731b4dc5eea4f5fd6560dec0be200000000"]'
[
  {
    "txid": "068f9bc8ce2312568dc78a779b8231555e6f05fb170dbbe9a6a30d51048d5580",
    "wtxid": "69d0ad20a1bbdc76521fe9f41518bfbb91cd1e215b5854e50d2b8d123f277acc",
    "allowed": true,
    "vsize": 99,
    "fees": {
      "base": 0.00010000
    }
  }
]
```

We can also run this through btcdeb to see more details on how this transaction is composed:

```Bash
$ btcdeb --txin=$txin --tx=0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e8346820140742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d6a9e304e069d07bc60fc351dff7e5599b11309731b4dc5eea4f5fd6560dec0be200000000
btcdeb 0.4.22 -- type `./btcdeb -h` for start up options
LOG: sign segwit taproot
notice: btcdeb has gotten quieter; use --verbose if necessary (this message is temporary)
input tx index = 0; tx input vout = 0; value = 100000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(ec409014a3, 0)
note: there is a for-clarity preamble (use --verbose for details)
2 op script loaded. type `help` for usage information
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951 | 742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d...
OP_CHECKSIG                                                      |
#0000 a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
btcdeb> step
		<> PUSH stack a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                      |   a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
                                                                 | 742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d...
#0001 OP_CHECKSIG
btcdeb>
EvalChecksig() sigversion=2
GenericTransactionSignatureChecker::CheckSchnorrSignature(64 len sig, 32 len pubkey, sigversion=2)
  sig         = 742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d6a9e304e069d07bc60fc351dff7e5599b11309731b4dc5eea4f5fd6560dec0be2
  pub key     = a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
- schnorr sighash = 2d10df9f49240748b120e75e94d6417eed7d906589b6964a16afde7a198de828
  pubkey.VerifySchnorrSignature(sig=742c016b800a80daa3fbc744642189b838e858ea4b63461ec23751457cd2f8d6a9e304e069d07bc60fc351dff7e5599b11309731b4dc5eea4f5fd6560dec0be2, sighash=2d10df9f49240748b120e75e94d6417eed7d906589b6964a16afde7a198de828):
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
$ tap --tx=$tx --txin=$txin $pubkey 2 "${script_alice}" "${script_bob}" 1
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
Resulting Bech32m address: bcrt1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gsm28t6c
Final control object = c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
```

Above we see a control object being generated. The first byte (`c1`) is the leaf + pubkey parity bit; the leaf is simply a version, that must be `c0`. The pubkey turned out to be uneven earlier, so the version is incremented by 1 (the parity bit), to `c1`. The following 32 bytes (64 characters) match our internal public key. Can you spot where the last 32 bytes -- `c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9` -- are coming from? They are actually the alice script leaf hash! By providing this, the verifier is able to reconstruct the root and verify that our script is a part of the commitment. Read up on Merkle trees if you're confused.

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
[+] COutPoint(ec409014a3, 0)
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
sighash (little endian) = 733a561a910ba91819df23ab6d0d034a155a7c69b8d05124ddf6ab4388485f36
NOTE: there is a placeholder signature at the end of the witness data for the resulting transaction below; this must be replaced with a 64 byte signature for the sighash given above
Resulting transaction: 0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e8346820340000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
```

Let's see how this transaction fairs when we debug it.

```Bash
$ btcdeb --txin=$txin --tx=0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e8346820340000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
[..]
8 op script loaded. type `help` for usage information
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
<<< taproot commitment >>>                                         |                                                               i: 0
Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205f... | k: 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce94...
Tweak: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5... |
CheckTapTweak                                                      |
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
CheckTapTweak                                                      |
<<< committed script >>>                                           |
OP_SHA256                                                          |
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   |
OP_EQUALVERIFY                                                     |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0001 Tweak: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
```

After one iteration (`i → 1`), we end up with `k` equal to the branch (#0, #1) value (which you can confirm by scrolling up).

The next step is calling the `CheckTapTweak()` method in the public key class, which takes the internal pubkey `p` and tweak+internal pubkey `k` and ensures that the tweaked pubkey `q` satisfies `tweak(p, k) = q`, where `tweak()` is defined as in BIP340-342. (The third argument, 1, is the parity bit.)

```Bash
btcdeb>
- looping over path (0..0)
- q.CheckTapTweak(p, k, 1) == success
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_SHA256                                                          | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   |
OP_EQUALVERIFY                                                     |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0002 CheckTapTweak
```

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
#0003 OP_SHA256
btcdeb>
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_EQUALVERIFY                                                     |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |   1c4672a4c6713bcb9495abba712be251bbeff723d79f001f81e5170b1d1627a5
OP_CHECKSIG                                                        |
#0004 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
btcdeb>
		<> POP  stack
		<> POP  stack
		<> PUSH stack
error: Script failed an OP_EQUALVERIFY operation
```

Unsurprisingly, our fake signature does *not* sha256-hash to the preimage hash that Bob requires. Luckily we know what the preimage is, because we created it at the very top. Let's put that in as the first script argument to tap (after the selected script index). We also want a signature by Bob in there, so let's also provide *Bob's private key* to tap. Alternatively we could run through to the end and use the sighash to generate a signature elsewhere.

```Bash
$ tap -k81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9 --tx=$tx --txin=$txin $pubkey 2 "${script_alice}" "${script_bob}" 1 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
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
signature: 54d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d57c523202b4650302667723f63dd5a87b2370ada51e08de0eccb27a80450ff9bf
Resulting transaction: 0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e834682044054d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d57c523202b4650302667723f63dd5a87b2370ada51e08de0eccb27a80450ff9bf20107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
```

This time we get a real signature (54d5..) and a resulting transaction. Let's run that transaction through btcdeb first of all (step through the taproot commitment stuff until we get to Bob's script):

```Bash
$ btcdeb --txin=$txin --tx=0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e834682044054d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d57c523202b4650302667723f63dd5a87b2370ada51e08de0eccb27a80450ff9bf20107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
[...]
btcdeb> step
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_SHA256                                                          |   107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   | 54d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d...
OP_EQUALVERIFY                                                     |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0002 CheckTapTweak
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
OP_EQUALVERIFY                                                     | 54d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d...
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |
OP_CHECKSIG                                                        |
#0003 OP_SHA256
btcdeb>
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_EQUALVERIFY                                                     |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_CHECKSIG                                                        | 54d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d...
#0004 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
btcdeb>
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
		<> POP  stack
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   | 54d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d...
OP_CHECKSIG                                                        |
#0005 OP_EQUALVERIFY
btcdeb>
		<> PUSH stack 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                        |   4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
                                                                   | 54d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d...
#0006 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
btcdeb>
EvalChecksig() sigversion=3
Eval Checksig Tapscript
- sig must not be empty: ok
- validation weight - 50 -> 235
- 32 byte pubkey (new type); schnorr sig check
GenericTransactionSignatureChecker::CheckSchnorrSignature(64 len sig, 32 len pubkey, sigversion=3)
  sig         = 54d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d57c523202b4650302667723f63dd5a87b2370ada51e08de0eccb27a80450ff9bf
  pub key     = 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
- schnorr sighash = 365f488843abf6dd2451d0b8697c5a154a030d6dab23df1918a90b911a563a73
  pubkey.VerifySchnorrSignature(sig=54d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d57c523202b4650302667723f63dd5a87b2370ada51e08de0eccb27a80450ff9bf, sighash=365f488843abf6dd2451d0b8697c5a154a030d6dab23df1918a90b911a563a73):
  result: success
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
                                                                   |                                                                 01
```

Yay! Let's send this transaction and see if it flies:

```Bash
$ bcli sendrawtransaction 020000000001011a02ddc9054dbde62125b3a057ec94982b4ebb915ff192a8ba29d5caf39c2fd50000000000ffffffff01905f0100000000001600149f39a4543d3111615aba6a4c25ed4690930a2bec04404d0eaf604c38a44420addbbe21bb8d53eb46a59751bfbf4ee1da0405f75f8f36a8ff35ffffe95ef35450466fafd13f6ee2343373cd8785712657e57f51168e8720107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
068f9bc8ce2312568dc78a779b8231555e6f05fb170dbbe9a6a30d51048d5580
$ bcli getrawtransaction 068f9bc8ce2312568dc78a779b8231555e6f05fb170dbbe9a6a30d51048d5580 1
{
  "txid": "068f9bc8ce2312568dc78a779b8231555e6f05fb170dbbe9a6a30d51048d5580",
  "hash": "235c81cf33e05eeccfa1c64a6bb0918cc4ecf52a266a1989fb32b937b83c4535",
  "version": 2,
  "size": 319,
  "vsize": 142,
  "weight": 565,
  "locktime": 0,
  "vin": [
    {
      "txid": "ec409014a3b1e7171cf498726bc7bc8bd249a04b65f30c7b8cb5c3079cf8f271",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "54d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d57c523202b4650302667723f63dd5a87b2370ada51e08de0eccb27a80450ff9bf",
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
        "asm": "0 ceb2d28afdcad1ae0fc2cf81cb929ba29e834682",
        "hex": "0014ceb2d28afdcad1ae0fc2cf81cb929ba29e834682",
        "address": "bcrt1qe6ed9zhaetg6ur7ze7quhy5m520gx35znudxan",
        "type": "witness_v0_keyhash"
      }
    }
  ],
  "hex": "0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e834682044054d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d57c523202b4650302667723f63dd5a87b2370ada51e08de0eccb27a80450ff9bf20107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000"
}
$
```

And we're done! Hope it was helpful. Please submit pull requests or issues with improvements to this document and/or btcdeb.

If you want to do this all manually by hand to really get your hands dirty, you can redo this exercise (with slightly different values) over [here](tapscript-example.md).
