# Tapscript example

This document describes one process with which you can create, from scratch, your own Tapscript output, fund it, and then spend one of its paths.

Note: you should start out at [the tap utility version of this document](tapscript-example-with-tap.md) unless you want to know the nitty gritty details.

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
intrnl      3bed2cb3a3acf7b6a8ef408420cc682d5520e26976d354254f528c965612054f    5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5

And preimage 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f with sha256(preimage) = 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
```

So the above two scripts expand into:
```
1. 144 OP_CHECKSEQUENCEVERIFY OP_DROP 9997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be OP_CHECKSIG
2. OP_SHA256 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 OP_EQUALVERIFY 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 OP_CHECKSIG
```

(now you might realize why people are so eager to *not* have to show all the paths when spending; not having to show the unnecessary alternative path(s) means a much smaller script and thus less fees)

Next, we will see how we can generate a merkle tree for these two.

## Generating a Taproot commitment

Without going into detail, in order to spend a Taproot output, you either have to sign with the *tweaked private key* or you have to provide (1) a script, (2) a proof that the script was actually *committed to* by the output, and (3) conditions satisfying the script, including signatures and the like.

We will do both, in that order.

To avoid risk of collisions when using hashes of things, Taproot introduces *tagged hashes*. Think of them as a regular old hash with a prefix (a tag), that was hashed and fed to it beforehand. We will use three types of tagged hashes:

* `TapLeaf`: a leaf node (e.g. one of our scripts)
* `TapBranch`: a branch node gluing leaf and branch nodes together in a tree (e.g. the parent node for our two scripts)
* `TapTweak`: a key tweaked with a script leaf/branch tree root (private or public)

These are derived as: `SHA256(SHA256(tag_as_utf8_string) || SHA26(tag_as_utf8_string) || msg)`, e.g. `SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || "foobar")` to `TapLeaf` the message `"foobar"`.

When we generate our output (i.e. commit to our scripts), we begin by creating the `TapLeaf` tags for each of the scripts. We then pair them together two at a time using `TapBranch`, and at the end, we create a tweak using `TapTweak` containing our internal public key and the merkle root, and then finally we tweak our internal public key with that. *That is our taproot key!* One caveat though: for each "merge", we have to order the pair, i.e. if left hash evaluates to `0x123abc` and right to `0x123abb`, we need to swap the hashes, so that left is always <= right.

Let's start by generating the `TapLeaf` entries.

Using `btcc`, we can get the script encoded variant of both. (Note: I am assuming you did `make install` on btcdeb; if not, prefix all commands with `./` and be sure that you're in the `btcdeb` folder)
```Bash
$ btcc 144 OP_CHECKSEQUENCEVERIFY OP_DROP 9997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be OP_CHECKSIG
029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac
$ btcc OP_SHA256 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 OP_EQUALVERIFY 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 OP_CHECKSIG
a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
```

(Sidenote: we use the magic value 'c0' below, which is the leaf version. Read up on the BIPs if you want details.)

We now generate the `TapLeaf` hashes:
```Bash
$ btcdeb
[..]
btcdeb> tf tagged-hash TapLeaf c0 prefix_compact_size(029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac)
c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
# ↑ this is the commitment hash for script 1, and this provided if we want to spend script 2
btcdeb> tf tagged-hash TapLeaf c0 prefix_compact_size(a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac)
632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce943b42
# ↑ this is the commitment hash for script 2, and this is provided if we want to spend script 1
# *** NOTE: c814... is greater than 632c..., so we have to swap the hashes when we put them into the
#           branch in the next step
btcdeb> tf tagged-hash TapBranch 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce943b42 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b
# ↑ this is the root of our merkle tree, before we do the tweak
btcdeb tf tagged-hash TapTweak 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b
0b0e6981ce6cac74d055d0e4c25e5b4455a083b3217761327867f26460e0a776
# ↑ this is the tweak; we now need to tweak our pubkey (note: the tweak is actually multiplied by the
#   generator to generate a point that is added to the pubkey; this is done under the hood by the
#   secp256k1 library, but is worth noting; you should not do this yourself)
btcdeb> tf taproot-tweak-pubkey 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 0b0e6981ce6cac74d055d0e4c25e5b4455a083b3217761327867f26460e0a776
03f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
# We got a uneven (03) pubkey f128a8...0c
```

Note: the pubkey we got was uneven (03). Later when we do a Tapscript spend, we need to remember this, or the tapscript commitment may fail.

We now have our pubkey f128a8...0c. We can bech32-encode it to get an actual address. (Note: bech32-encode is temporarily hard-coded to use regtest version 1 addresses. This will be made configurable.)

```Bash
btcdeb> tf bech32-encode f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
"bcrt1p7y52329xxmse7q9gq9542rldlsntdawaqnvntmz99z224kfcauxqg59zqx"
```

Warning: be sure to remove the evenness byte from the above! If you do 03f128a8... you will get something that cannot be spent!

Now send a (small!) amount to this address, and check the transaction. It should say unknown witness for the output.

```Bash
$ bitcoin-cli sendtoaddress bcrt1p7y52329xxmse7q9gq9542rldlsntdawaqnvntmz99z224kfcauxqg59zqx 0.0001
d0940a43af208262dba1868d7accf2bf765da43be3e299e388a1d987eb4598e7
# (if you get fee estimation failed errors when sending, do `bitcoin-cli settxfee 0.00001` and try again)
$ bitcoin-cli getrawtransaction d0940a43af208262dba1868d7accf2bf765da43be3e299e388a1d987eb4598e7 1
{
  "in_active_chain": true,
  "txid": "d0940a43af208262dba1868d7accf2bf765da43be3e299e388a1d987eb4598e7",
  "hash": "a726cb1e6114d45f385410e24ea286e8cb7c9ce1c40aaf9eb4e2113a336df7e4",
  "version": 2,
  "size": 234,
  "vsize": 153,
  "weight": 609,
  "locktime": 13,
  "vin": [
    {
      "txid": "e9742c89130e28a559810849937079e36dcba80a49d155057eb399e2e1a43650",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "304402206c4c1c9e2fa82d087e5c1a6256f2bcd7cab3b915bf2f6b782a80045f9dc7a9b2022034c720cbbab2e75cbd8a35bc99d148f408b16205592e80200bf2f491bb0fa88b01",
        "02077c102914911f57b8c1881e207ea09297024803e1c10ce3f20453c2c3f735c6"
      ],
      "sequence": 4294967294
    }
  ],
  "vout": [
    {
      "value": 0.10000000,
      "n": 0,
      "scriptPubKey": {
        "asm": "1 f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c",
        "hex": "5120f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c",
        "reqSigs": 1,
        "type": "witness_v1_taproot",
        "addresses": [
          "bcrt1p7y52329xxmse7q9gq9542rldlsntdawaqnvntmz99z224kfcauxqg59zqx"
        ]
      }
    },
    {
      "value": 49.89999847,
      "n": 1,
      "scriptPubKey": {
        "asm": "0 cfb604b3feadf3367e96c701abd4912d0c99877f",
        "hex": "0014cfb604b3feadf3367e96c701abd4912d0c99877f",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "bcrt1qe7mqfvl74henvl5kcuq6h4y395xfnpml96t6lj"
        ]
      }
    }
  ],
  "hex": "020000000001015036a4e1e299b37e0555d1490aa8cb6de379709349088159a5280e13892c74e90000000000feffffff028096980000000000225120f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0ce75a6d2901000000160014cfb604b3feadf3367e96c701abd4912d0c99877f0247304402206c4c1c9e2fa82d087e5c1a6256f2bcd7cab3b915bf2f6b782a80045f9dc7a9b2022034c720cbbab2e75cbd8a35bc99d148f408b16205592e80200bf2f491bb0fa88b012102077c102914911f57b8c1881e207ea09297024803e1c10ce3f20453c2c3f735c60d000000",
  "blockhash": "657719912c20e44e7b98c3eda01bd2e493186d16737987800e766ecf704898e6",
  "confirmations": 1,
  "time": 1597817267,
  "blocktime": 1597817267
}
```

We find our UTXO at index 0 above (yours may be at a different index, e.g. 1). Note type being witness_v1_taproot, and note asm starting with a 1, as opposed to a 0. this is the segwit version.

We will need the hex value from this one later. We refer to it as "txin" and set a shell var to it for now:

```Bash
$ txin=020000000001015036a4e1e299b37e0555d1490aa8cb6de379709349088159a5280e13892c74e90000000000feffffff028096980000000000225120f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0ce75a6d2901000000160014cfb604b3feadf3367e96c701abd4912d0c99877f0247304402206c4c1c9e2fa82d087e5c1a6256f2bcd7cab3b915bf2f6b782a80045f9dc7a9b2022034c720cbbab2e75cbd8a35bc99d148f408b16205592e80200bf2f491bb0fa88b012102077c102914911f57b8c1881e207ea09297024803e1c10ce3f20453c2c3f735c60d000000
```

## Taproot spend

(--- unfinished below; the approach should still mostly work ---)

It is now possible to do a direct taproot spend using the internal privkey, and our tweak. We will use testmempoolaccept for this one, as it's too boring to waste an entire UTXO on.

First, we need to create a transaction that spends from these inputs.

```Bash
$ bitcoin-cli getnewaddress
sb1qpkxrw8snhrzx8gkkn4d5w34tr0zeahlk83vnl0
$ bitcoin-cli createrawtransaction '[{"txid":"d4461a7d5d4120f7c3fd62c2f665b546129e4527a2bc2f1f7e7eedf4f77eba62", "vout":0}]' '[{"sb1qpkxrw8snhrzx8gkkn4d5w34tr0zeahlk83vnl0":0.00009}]'
020000000162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff600000000
```

Now we need to tweak it. This is the messy part, but stay with me. We turn it into a Segwit transaction by adding the dummy vin and 0x01 flag: take the first 8 characters (the 32-bit version):

> 02000000

add 0001 to it (0 size vin, flags=01)

> 020000000001

then add the rest up until but *excluding* the last 8 characters (all zeroes):

> 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6

Before we put those last 8 characters on, we add the witness commitment. This is an array, of arrays, of arrays of bytes. Or an array of arrays of binary blobs. Each outer array corresponds to one input, and this is explicit, i.e. we do *not* put the compact size of the outer array into the serialization; this is implicitly derived from the input array, which must be the same size. The inner array, i.e. the array of binary blobs, or the array containing arrays of bytes, does have a size, however.

In our case, we have 1 input, so there's an array containing binary blobs. The number of entries? Depends on which script we're executing. For Taproot spends, we need to push the signature, and... that's it. The signature has to be 64 bytes, but alas, we don't have a way to sign yet, so let's just make something random that is 64 bytes long.

> 01 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f

Then the locktime (last 8 zeroes), and we have a starting point:

> 020000000001 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6 01 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 00000000

Hint: You can *keep* the spacing for easier tweaking/overview, by wrapping the argument in quotes in the call to btcdeb.

We're now ready to do our first attempt at spending our transaction. Our signature is crap, but we'll get to that.

```Bash
$ btcdeb --txin=$txin --tx='020000000001 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6 01 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 00000000'
got segwit transaction 61d6e879d1c791806283d13d561870f3bcecab877b1b719e207380f611bd4760:
CTransaction(hash=61d6e879d1, ver=2, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(d4461a7d5d, 0), scriptSig=)
    CScriptWitness(000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f)
    CTxOut(nValue=0.00009000, scriptPubKey=00140d8c371e13b8c463a2d69d5b47)

got input tx #0 d4461a7d5d4120f7c3fd62c2f665b546129e4527a2bc2f1f7e7eedf4f77eba62:
CTransaction(hash=d4461a7d5d, ver=2, vin.size=1, vout.size=2, nLockTime=335)
    CTxIn(COutPoint(65c22aa264, 1), scriptSig=, nSequence=4294967294)
    CScriptWitness(304402203562d886132f4b1c2872759874e02eddbebe6334c50c5cf74c7a07d336a51410022040d7961e242d5dcb435bdc05fa2f34b415f8073251e1868ca8ba44f67982cb1c01, 0242eb71f5a65b85e1ebd959008e46e26bd6439ba98a97e4276344bd564eb6921d)
    CTxOut(nValue=0.00010000, scriptPubKey=512096f4011191d236826a07b98929)
    CTxOut(nValue=49.99679232, scriptPubKey=00145d056890231a3d66b9360ca320)

input tx index = 0; tx input vout = 0; value = 10000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d4461a7d5d, 0)
2 op script loaded. type `help` for usage information
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4 | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
OP_CHECKSIG                                                      |
#0000 96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
```

OK, btcdeb is able to parse the transaction and gives us the starting point in the very simple program. You should know that in reality, there *is* no program at all; the signature check is done upon recognizing the TAPROOT spend pattern (single object on the stack), but btcdeb bakes it into a `<push> CHECKSIG` quasi script.

Let's step until the end and see how our "signature" does:

```
btcdeb> step
		<> PUSH stack 96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                      |   96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
                                                                 | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
#0001 OP_CHECKSIG
btcdeb>
GenericTransactionSignatureChecker::CheckSigSchnorr(64 len sig, 32 len pubkey, sigversion=2)
  sig         = 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
  pub key     = 96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
#001 00
#001 00
#004 02000000
#004 00000000
#032 518c069d99921479cf4ee88f5ae7d439aadb00941ae697dd679fd057601d1b58
#032 8e965763e6a4bbc1088a94bf6c9cb3cbbdb4955f88355c807362a0fd43de4e3a
#032 ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e
#032 78c8d3aa6e969b820788e580db66e5675bd03d08dcfe56c4e3430c56598efe18
#001 00
#001 22
#034 512096f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
#004 00000000
- schnorr sighash = 48f47c4aad9ad4d0ea6671d10c34eb34b70255f12bd4c72b77c19805e274765b
  pubkey.VerifySchnorrSignature(sig=000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f, sighash=48f47c4aad9ad4d0ea6671d10c34eb34b70255f12bd4c72b77c19805e274765b):
  result: FAILURE
		<> POP  stack
		<> POP  stack
		<> PUSH stack
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
                                                                 |                                                                 0x
```

OK yeah that didn't go too well. However, btcdeb has now given us a vital clue. The only one we need, in fact, to complete this transaction: the signature hash (abbreviate "sighash") -- it is `48f47c4aad9ad4d0ea6671d10c34eb34b70255f12bd4c72b77c19805e274765b` (big endian, so we need to *reverse* it), and you can see it above a few lines above the "result: FAILURE" part. With that, and our privkey (which we created at the start) tweaked with that tweak we created, we can now create an *actual* signature!

```Bash
btcdeb> tf taproot-tweak-seckey 3bed2cb3a3acf7b6a8ef408420cc682d5520e26976d354254f528c965612054f 0b0e6981ce6cac74d055d0e4c25e5b4455a083b3217761327867f26460e0a776
46fb96357219a42b79451168e32ac371aac1661c984ab557c7ba7efab6f2acc5
# we can verify that this is correct by using get-xpubkey and comparing this to our pubkey we made before
btcdeb> tf get-xpubkey 46fb96357219a42b79451168e32ac371aac1661c984ab557c7ba7efab6f2acc5
96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
btcdeb> tf sign reverse(48f47c4aad9ad4d0ea6671d10c34eb34b70255f12bd4c72b77c19805e274765b) 46fb96357219a42b79451168e32ac371aac1661c984ab557c7ba7efab6f2acc5
4cfb9f2255194929156c1dbbc38d9a3c4fc0f209b4b7aee58c5d2b2020a2cea719c9f41ef2b81327c1ee964c7392251039a8c79369bd57c7f9a8e071227822a3
```

We can now replace our `00010203...` thingie with the above and try again.

```Bash
$ btcdeb --txin=$txin --tx='020000000001 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6 01 40 4cfb9f2255194929156c1dbbc38d9a3c4fc0f209b4b7aee58c5d2b2020a2cea719c9f41ef2b81327c1ee964c7392251039a8c79369bd57c7f9a8e071227822a3 00000000'
[...]
#0001 OP_CHECKSIG
btcdeb>
GenericTransactionSignatureChecker::CheckSigSchnorr(64 len sig, 32 len pubkey, sigversion=2)
  sig         = 4cfb9f2255194929156c1dbbc38d9a3c4fc0f209b4b7aee58c5d2b2020a2cea719c9f41ef2b81327c1ee964c7392251039a8c79369bd57c7f9a8e071227822a3
  pub key     = 96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
#001 00
#001 00
#004 02000000
#004 00000000
#032 518c069d99921479cf4ee88f5ae7d439aadb00941ae697dd679fd057601d1b58
#032 8e965763e6a4bbc1088a94bf6c9cb3cbbdb4955f88355c807362a0fd43de4e3a
#032 ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e
#032 78c8d3aa6e969b820788e580db66e5675bd03d08dcfe56c4e3430c56598efe18
#001 00
#001 22
#034 512096f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
#004 00000000
- schnorr sighash = 48f47c4aad9ad4d0ea6671d10c34eb34b70255f12bd4c72b77c19805e274765b
  pubkey.VerifySchnorrSignature(sig=4cfb9f2255194929156c1dbbc38d9a3c4fc0f209b4b7aee58c5d2b2020a2cea719c9f41ef2b81327c1ee964c7392251039a8c79369bd57c7f9a8e071227822a3, sighash=48f47c4aad9ad4d0ea6671d10c34eb34b70255f12bd4c72b77c19805e274765b):
  result: success
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
                                                                 |                                                                 01
```

And we're good. If we did `sendrawtransaction` now, the transaction would be accepted and be eventually mined into a block like normal. We don't wanna do that though. We have those two scripts after all, let's not waste that effort! We do want to ask Bitcoin Core about the transaction though. The handy `testmempoolaccept` RPC function lets us do exactly that.

```Bash
$ bitcoin-cli testmempoolaccept '["0200000000010162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff601404cfb9f2255194929156c1dbbc38d9a3c4fc0f209b4b7aee58c5d2b2020a2cea719c9f41ef2b81327c1ee964c7392251039a8c79369bd57c7f9a8e071227822a300000000"]'
[
  {
    "txid": "61d6e879d1c791806283d13d561870f3bcecab877b1b719e207380f611bd4760",
    "allowed": true
  }
]
```

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

To do the tapscript spend, we need to provide a "control object" which describes the path leading to our particular script. The two possible control objects are:
* Use Alice's script: `<control byte with leaf & negation bit> || <internal pubkey> || <Bob script tagged hash>`
* Use Bob's script: `<control byte with leaf & negation bit> || <internal pubkey> || <Alice script tagged hash>`

We wanna go the second route; the leaf in the control byte is the hex value c0 (decimal 192), the negation bit, if you recall from when we funded this thing, should be set to 1, so we get c1 (193)), the internal pubkey is 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5, and Alice's script tagged hash is c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9, giving us:

> c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9

We need to push the above as a single push operation; counting it, we get 65 bytes, which in hex is 0x41. So we end up with

> 41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9

We also need to reveal the script we are executing, as this is required to determine whether our tapscript commitment is valid: this is a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac, and it's 69 bytes (=0x45). Combined (first program, then control object) we have

> 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
> 41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9

and our script, when we replace the witness stuff above with the new data (prefixed with a 02 for "2 items on stack"):

> 020000000001 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6 02 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000

(Note that you can use the `prefix-compact-size` transform inside btcdeb to generate the size prefixed variants, e.g. `tf prefix-compact-size c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9` inside btcdeb gives `41c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9`.)

```Bash
$ btcdeb --txin=$txin --tx='020000000001 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6 02 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000'
btcdeb 0.2.19 -- type `./btcdeb -h` for start up options
got segwit transaction 61d6e879d1c791806283d13d561870f3bcecab877b1b719e207380f611bd4760:
CTransaction(hash=61d6e879d1, ver=2, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(d4461a7d5d, 0), scriptSig=)
    CScriptWitness(a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac, c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9)
    CTxOut(nValue=0.00009000, scriptPubKey=00140d8c371e13b8c463a2d69d5b47)

got input tx #0 d4461a7d5d4120f7c3fd62c2f665b546129e4527a2bc2f1f7e7eedf4f77eba62:
CTransaction(hash=d4461a7d5d, ver=2, vin.size=1, vout.size=2, nLockTime=335)
    CTxIn(COutPoint(65c22aa264, 1), scriptSig=, nSequence=4294967294)
    CScriptWitness(304402203562d886132f4b1c2872759874e02eddbebe6334c50c5cf74c7a07d336a51410022040d7961e242d5dcb435bdc05fa2f34b415f8073251e1868ca8ba44f67982cb1c01, 0242eb71f5a65b85e1ebd959008e46e26bd6439ba98a97e4276344bd564eb6921d)
    CTxOut(nValue=0.00010000, scriptPubKey=512096f4011191d236826a07b98929)
    CTxOut(nValue=49.99679232, scriptPubKey=00145d056890231a3d66b9360ca320)

input tx index = 0; tx input vout = 0; value = 10000
got witness stack of size 2
34 bytes (v0=P2WSH, v1=taproot/tapscript)
Verifying taproot commitment:
- control  = c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
- program  = 96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
- script   = a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
- path len = 1
- p        = 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5
- q        = 96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
- k        = 423b94cec6e38364eda58e7825e582cb8ef75c13236e4191629cf2b432862c63          (tap leaf hash)
  (TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac))
- looping over path (0..0)
  - 0: node_begin = -1806693135; taproot control node match -> k first
  (TapBranch(TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac) || Span<33,32>=c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9))
  - 0: k -> 6b9f0cd659a5c64f4f5ac4f84e7998dae7fec41b47f5d7da6da9e21f8c6f6441
- final k  = 76a7e06064f2677832617721b383a055445b5ec2e4d055d074ac6cce81690e0b
  (TapTweak(internal_pubkey=5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 || TapBranch(TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac) || Span<33,32>=c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9)))
- q.CheckPayToContract(p, k, 1) == success
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d4461a7d5d, 0)
5 op script loaded. type `help` for usage information
script                                                           |  stack
-----------------------------------------------------------------+--------
OP_SHA256                                                        |
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 |
OP_EQUALVERIFY                                                   |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |
OP_CHECKSIG                                                      |
#0000 OP_SHA256
```

The tapscript commitment succeeded. Yay! Now as you can see we still need to add the inputs that satisfy the script itself. We will be adding those on the left hand side of the program || control object blob in the witness. Generally speaking, tapscript spending witness stack looks like: `<argN> ... <arg2> <arg1> <script> <control object>`.

* Firstly, the preimage which, when hashed, turns into the above: 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
* Second, the signature for the script. We don't have one, yet, so let's just put 64 random bytes in and have btcdeb tell us the sighash.

Flipped around, since args are opposite order:

> 020000000001 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6 04 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 20 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000

```Bash
$ btcdeb --txin=$txin --tx='020000000001 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6 04 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 20 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000'
btcdeb 0.2.19 -- type `./btcdeb -h` for start up options
LOG: sighash
LOG: sign
LOG: segwit
LOG: taproot
got segwit transaction 61d6e879d1c791806283d13d561870f3bcecab877b1b719e207380f611bd4760:
CTransaction(hash=61d6e879d1, ver=2, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(d4461a7d5d, 0), scriptSig=)
    CScriptWitness(000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f, 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f, a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac, c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9)
    CTxOut(nValue=0.00009000, scriptPubKey=00140d8c371e13b8c463a2d69d5b47)

got input tx #0 d4461a7d5d4120f7c3fd62c2f665b546129e4527a2bc2f1f7e7eedf4f77eba62:
CTransaction(hash=d4461a7d5d, ver=2, vin.size=1, vout.size=2, nLockTime=335)
    CTxIn(COutPoint(65c22aa264, 1), scriptSig=, nSequence=4294967294)
    CScriptWitness(304402203562d886132f4b1c2872759874e02eddbebe6334c50c5cf74c7a07d336a51410022040d7961e242d5dcb435bdc05fa2f34b415f8073251e1868ca8ba44f67982cb1c01, 0242eb71f5a65b85e1ebd959008e46e26bd6439ba98a97e4276344bd564eb6921d)
    CTxOut(nValue=0.00010000, scriptPubKey=512096f4011191d236826a07b98929)
    CTxOut(nValue=49.99679232, scriptPubKey=00145d056890231a3d66b9360ca320)

input tx index = 0; tx input vout = 0; value = 10000
got witness stack of size 4
34 bytes (v0=P2WSH, v1=taproot/tapscript)
Verifying taproot commitment:
- control  = c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
- program  = 96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
- script   = a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
- path len = 1
- p        = 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5
- q        = 96f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
- k        = 423b94cec6e38364eda58e7825e582cb8ef75c13236e4191629cf2b432862c63          (tap leaf hash)
  (TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac))
- looping over path (0..0)
  - 0: node_begin = 920652897; taproot control node match -> k first
  (TapBranch(TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac) || Span<33,32>=c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9))
  - 0: k -> 6b9f0cd659a5c64f4f5ac4f84e7998dae7fec41b47f5d7da6da9e21f8c6f6441
- final k  = 76a7e06064f2677832617721b383a055445b5ec2e4d055d074ac6cce81690e0b
  (TapTweak(internal_pubkey=5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 || TapBranch(TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac) || Span<33,32>=c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9)))
- q.CheckPayToContract(p, k, 1) == success
valid script
- generating prevout hash from 1 ins
[+] COutPoint(d4461a7d5d, 0)
5 op script loaded. type `help` for usage information
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_SHA256                                                        |   107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
OP_EQUALVERIFY                                                   |
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |
OP_CHECKSIG                                                      |
#0000 OP_SHA256
btcdeb> step
		<> POP  stack
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333 |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_EQUALVERIFY                                                   | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |
OP_CHECKSIG                                                      |
#0001 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
btcdeb>
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_EQUALVERIFY                                                   |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_CHECKSIG                                                      | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
#0002 OP_EQUALVERIFY
btcdeb>
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
		<> POP  stack
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10 | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
OP_CHECKSIG                                                      |
#0003 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
btcdeb>
		<> PUSH stack 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                      |   4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
                                                                 | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
#0004 OP_CHECKSIG
btcdeb>
Eval Checksig Tapscript
- sig must not be empty: ok
- validation weight - 50 -> 235
- 32 byte pubkey (new type); schnorr sig check
GenericTransactionSignatureChecker::CheckSigSchnorr(64 len sig, 32 len pubkey, sigversion=3)
  sig         = 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
  pub key     = 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
#001 00
#001 00
#004 02000000
#004 00000000
#032 518c069d99921479cf4ee88f5ae7d439aadb00941ae697dd679fd057601d1b58
#032 8e965763e6a4bbc1088a94bf6c9cb3cbbdb4955f88355c807362a0fd43de4e3a
#032 ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e
#032 78c8d3aa6e969b820788e580db66e5675bd03d08dcfe56c4e3430c56598efe18
#001 02
#001 22
#034 512096f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
#004 00000000
#032 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce943b42
#001 00
#004 ffffffff
- schnorr sighash = 2358796e44e5c16e678f613dc0550740123a682c17680b7467985d9145d478db
  pubkey.VerifySchnorrSignature(sig=000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f, sighash=2358796e44e5c16e678f613dc0550740123a682c17680b7467985d9145d478db):
  result: FAILURE
- schnorr sig check failed
error: Signature must be zero for failed CHECK(MULTI)SIG operation
btcdeb>
```

OK. The sighash is `2358796e44e5c16e678f613dc0550740123a682c17680b7467985d9145d478db`. We can sign it, since we have Bob's privkey `81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9`. Remember; sighash is a hash. We need to reverse it below.

```Bash
btcdeb> tf sign reverse(2358796e44e5c16e678f613dc0550740123a682c17680b7467985d9145d478db) 81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9
f82df2168f776da2043a532a2e63404307bd4a6092266216557b51a0152adbbe67ae501bdc754f01eaa3a1d22181e2fd29416c72147cb75d5c63e07b344d3fb9
```

Now let's put the real signature in and try again.

> 020000000001 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6 04 40 f82df2168f776da2043a532a2e63404307bd4a6092266216557b51a0152adbbe67ae501bdc754f01eaa3a1d22181e2fd29416c72147cb75d5c63e07b344d3fb9 20 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000

```Bash
$ btcdeb --txin=$txin --tx='020000000001 0162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff6 04 40 f82df2168f776da2043a532a2e63404307bd4a6092266216557b51a0152adbbe67ae501bdc754f01eaa3a1d22181e2fd29416c72147cb75d5c63e07b344d3fb9 20 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000'
[...]
#0004 OP_CHECKSIG
btcdeb>
Eval Checksig Tapscript
- sig must not be empty: ok
- validation weight - 50 -> 235
- 32 byte pubkey (new type); schnorr sig check
GenericTransactionSignatureChecker::CheckSigSchnorr(64 len sig, 32 len pubkey, sigversion=3)
  sig         = f82df2168f776da2043a532a2e63404307bd4a6092266216557b51a0152adbbe67ae501bdc754f01eaa3a1d22181e2fd29416c72147cb75d5c63e07b344d3fb9
  pub key     = 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
#001 00
#001 00
#004 02000000
#004 00000000
#032 518c069d99921479cf4ee88f5ae7d439aadb00941ae697dd679fd057601d1b58
#032 8e965763e6a4bbc1088a94bf6c9cb3cbbdb4955f88355c807362a0fd43de4e3a
#032 ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e
#032 78c8d3aa6e969b820788e580db66e5675bd03d08dcfe56c4e3430c56598efe18
#001 02
#001 22
#034 512096f4011191d236826a07b98929802aa3b7b7e32cea86aca4f82ce89fa34fdcd4
#004 00000000
#032 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce943b42
#001 00
#004 ffffffff
- schnorr sighash = 2358796e44e5c16e678f613dc0550740123a682c17680b7467985d9145d478db
  pubkey.VerifySchnorrSignature(sig=f82df2168f776da2043a532a2e63404307bd4a6092266216557b51a0152adbbe67ae501bdc754f01eaa3a1d22181e2fd29416c72147cb75d5c63e07b344d3fb9, sighash=2358796e44e5c16e678f613dc0550740123a682c17680b7467985d9145d478db):
  result: success
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
                                                                 |                                                                 01
```

Success! Let's broadcast this one to the network:

```Bash
$ bitcoin-cli sendrawtransaction 0200000000010162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff60440f82df2168f776da2043a532a2e63404307bd4a6092266216557b51a0152adbbe67ae501bdc754f01eaa3a1d22181e2fd29416c72147cb75d5c63e07b344d3fb920107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
61d6e879d1c791806283d13d561870f3bcecab877b1b719e207380f611bd4760
$ bitcoin-cli getrawtransaction 61d6e879d1c791806283d13d561870f3bcecab877b1b719e207380f611bd4760 1
{
  "txid": "61d6e879d1c791806283d13d561870f3bcecab877b1b719e207380f611bd4760",
  "hash": "a86607a4f1a1512fca898ceb25ff260d726fbd22b24af5aa11b282da0eadee6e",
  "version": 2,
  "size": 319,
  "vsize": 142,
  "weight": 565,
  "locktime": 0,
  "vin": [
    {
      "txid": "d4461a7d5d4120f7c3fd62c2f665b546129e4527a2bc2f1f7e7eedf4f77eba62",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "f82df2168f776da2043a532a2e63404307bd4a6092266216557b51a0152adbbe67ae501bdc754f01eaa3a1d22181e2fd29416c72147cb75d5c63e07b344d3fb9",
        "107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f",
        "a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac",
        "c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.00009000,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 0d8c371e13b8c463a2d69d5b4746ab1bc59edff6",
        "hex": "00140d8c371e13b8c463a2d69d5b4746ab1bc59edff6",
        "reqSigs": 1,
        "type": "witness_v0_keyhash",
        "addresses": [
          "sb1qpkxrw8snhrzx8gkkn4d5w34tr0zeahlk83vnl0"
        ]
      }
    }
  ],
  "hex": "0200000000010162ba7ef7f4ed7e7e1f2fbca227459e1246b565f6c262fdc3f720415d7d1a46d40000000000ffffffff0128230000000000001600140d8c371e13b8c463a2d69d5b4746ab1bc59edff60440f82df2168f776da2043a532a2e63404307bd4a6092266216557b51a0152adbbe67ae501bdc754f01eaa3a1d22181e2fd29416c72147cb75d5c63e07b344d3fb920107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000",
  "blockhash": "00000f913152865b1030a8cbd39656abadebbae3a6f1b747c3e638f567997b2a",
  "confirmations": 1,
  "time": 1580286167,
  "blocktime": 1580286167
}
```

And we're done! Hope it was helpful. Please submit pull requests or issues with improvements to this document and/or btcdeb.
