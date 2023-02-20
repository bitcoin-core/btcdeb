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
btcdeb> tf tagged-hash TapTweak 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b
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
btcdeb> tf bech32m-encode f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
"bcrt1p7y52329xxmse7q9gq9542rldlsntdawaqnvntmz99z224kfcauxqag4w9y"
```

Warning: be sure to remove the evenness byte from the above! If you do 03f128a8... you will get something that cannot be spent!

Now send a (small!) amount to this address, and check the transaction. It should say unknown witness for the output.

```Bash
$ alias bcli='bitcoin-cli -regtest' # change this to whatever command you use to access bitcoin-cli
$ bcli sendtoaddress bcrt1p7y52329xxmse7q9gq9542rldlsntdawaqnvntmz99z224kfcauxqag4w9y 0.0001
303d28a45ad1234fd8092df147ae52464a4b7de0d343a2d79dc28dd7611dd25a
# (if you get fee estimation failed errors when sending, do `bcli settxfee 0.00001` and try again)
$ bcli getrawtransaction 303d28a45ad1234fd8092df147ae52464a4b7de0d343a2d79dc28dd7611dd25a 1
{
  "txid": "303d28a45ad1234fd8092df147ae52464a4b7de0d343a2d79dc28dd7611dd25a",
  "hash": "18cf1e2f860b6e416009531b1e0864157b842e961404ff4d9e5ac0170450a035",
  "version": 2,
  "size": 234,
  "vsize": 153,
  "weight": 609,
  "locktime": 202,
  "vin": [
    {
      "txid": "7cdda95c72df7648cbeac72591f019ea693326f18d9db3d6db683d498e32afbf",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "30440220472c552bc77523659aad75aac0674c723c058b80484f5186769c03cb0287b52f02200b0e449a51f185017a64c1261c852e51c2cbb4fee949a50d634224dfb27d23f601",
        "0344de9257311c16349ff0acd2be071433e3a1de0169ed900ae3f2e81f0b3f37fc"
      ],
      "sequence": 4294967294
    }
  ],
  "vout": [
    {
      "value": 0.00010000,
      "n": 0,
      "scriptPubKey": {
        "asm": "1 f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c",
        "hex": "5120f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c",
        "address": "bcrt1p7y52329xxmse7q9gq9542rldlsntdawaqnvntmz99z224kfcauxqag4w9y",
        "type": "witness_v1_taproot"
      }
    },
    {
      "value": 49.99918776,
      "n": 1,
      "scriptPubKey": {
        "asm": "0 801addecfc3d8a646ad95a2d48b2e729ec12e39b",
        "hex": "0014801addecfc3d8a646ad95a2d48b2e729ec12e39b",
        "address": "bcrt1qsqddmm8u8k9xg6ketgk53vh898kp9cum8ra3l2",
        "type": "witness_v0_keyhash"
      }
    }
  ],
  "hex": "02000000000101bfaf328e493d68dbd6b39d8df1263369ea19f09125c7eacb4876df725ca9dd7c0000000000feffffff021027000000000000225120f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0cb8b4042a01000000160014801addecfc3d8a646ad95a2d48b2e729ec12e39b024730440220472c552bc77523659aad75aac0674c723c058b80484f5186769c03cb0287b52f02200b0e449a51f185017a64c1261c852e51c2cbb4fee949a50d634224dfb27d23f601210344de9257311c16349ff0acd2be071433e3a1de0169ed900ae3f2e81f0b3f37fcca000000"
}
```

We find our UTXO at index 0 above (yours may be at a different index, e.g. 1). Note type being witness_v1_taproot, and note asm starting with a 1, as opposed to a 0. this is the segwit version.

We will need the hex value from this one later. We refer to it as "txin" and set a shell var to it for now:

```Bash
$ txin=02000000000101bfaf328e493d68dbd6b39d8df1263369ea19f09125c7eacb4876df725ca9dd7c0000000000feffffff021027000000000000225120f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0cb8b4042a01000000160014801addecfc3d8a646ad95a2d48b2e729ec12e39b024730440220472c552bc77523659aad75aac0674c723c058b80484f5186769c03cb0287b52f02200b0e449a51f185017a64c1261c852e51c2cbb4fee949a50d634224dfb27d23f601210344de9257311c16349ff0acd2be071433e3a1de0169ed900ae3f2e81f0b3f37fcca000000
```

## Taproot spend

It is now possible to do a direct taproot spend using the internal privkey, and our tweak. We will use testmempoolaccept for this one, as it's too boring to waste an entire UTXO on.

First, we need to create a transaction that spends from these inputs.

```Bash
$ bcli getnewaddress
bcrt1qja4zf8t0nq2pnqwu2nzndlseajftn96m38eecx
$ bcli createrawtransaction '[{"txid":"303d28a45ad1234fd8092df147ae52464a4b7de0d343a2d79dc28dd7611dd25a", "vout":0}]' '[{"bcrt1qja4zf8t0nq2pnqwu2nzndlseajftn96m38eecx":0.00009}]'
02000000015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b00000000
```

Now we need to tweak it. This is the messy part, but stay with me. We turn it into a Segwit transaction by adding the dummy vin and 0x01 flag: take the first 8 characters (the 32-bit version):

> 02000000

add 0001 to it (0 size vin, flags=01)

> 020000000001

then add the rest up until but *excluding* the last 8 characters (all zeroes):

> 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b

Before we put those last 8 characters on, we add the witness commitment. This is an array, of arrays, of arrays of bytes. Or an array of arrays of binary blobs. Each outer array corresponds to one input, and this is explicit, i.e. we do *not* put the compact size of the outer array into the serialization; this is implicitly derived from the input array, which must be the same size. The inner array, i.e. the array of binary blobs, or the array containing arrays of bytes, does have a size, however.

In our case, we have 1 input, so there's an array containing binary blobs. The number of entries? Depends on which script we're executing. For Taproot spends, we need to push the signature, and... that's it. The signature has to be 64 bytes, but alas, we don't have a way to sign yet, so let's just make something random that is 64 bytes long.

> 01 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f

Then the locktime (last 8 zeroes), and we have a starting point:

> 020000000001 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b 01 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 00000000

Hint: You can *keep* the spacing for easier tweaking/overview, by wrapping the argument in quotes in the call to btcdeb.

We're now ready to do our first attempt at spending our transaction. Our signature is crap, but we'll get to that.

```Bash
$ btcdeb --verbose --txin=$txin --tx='020000000001 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b 01 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 00000000'
got segwit transaction 275f90dcfc8b6c81ea54ee6e7648b3f628ee411ef11d1fdaf9c0074b04dbfef9:
CTransaction(hash=275f90dcfc, ver=2, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(303d28a45a, 0), scriptSig=)
    CScriptWitness(000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f)
    CTxOut(nValue=0.00009000, scriptPubKey=0014976a249d6f98141981dc54c536)

got input tx #0 303d28a45ad1234fd8092df147ae52464a4b7de0d343a2d79dc28dd7611dd25a:
CTransaction(hash=303d28a45a, ver=2, vin.size=1, vout.size=2, nLockTime=202)
    CTxIn(COutPoint(7cdda95c72, 0), scriptSig=, nSequence=4294967294)
    CScriptWitness(30440220472c552bc77523659aad75aac0674c723c058b80484f5186769c03cb0287b52f02200b0e449a51f185017a64c1261c852e51c2cbb4fee949a50d634224dfb27d23f601, 0344de9257311c16349ff0acd2be071433e3a1de0169ed900ae3f2e81f0b3f37fc)
    CTxOut(nValue=0.00010000, scriptPubKey=5120f128a8a8a636e19f00a8016955)
    CTxOut(nValue=49.99918776, scriptPubKey=0014801addecfc3d8a646ad95a2d48)

input tx index = 0; tx input vout = 0; value = 10000
got witness stack of size 1
34 bytes (v0=P2WSH, v1=taproot/tapscript)
valid script
- generating prevout hash from 1 ins
[+] COutPoint(303d28a45a, 0)
2 op script loaded. type `help` for usage information
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
OP_CHECKSIG                                                      |
#0000 f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
```

OK, btcdeb is able to parse the transaction and gives us the starting point in the very simple program. You should know that in reality, there *is* no program at all; the signature check is done upon recognizing the TAPROOT spend pattern (single object on the stack), but btcdeb bakes it into a `<push> CHECKSIG` quasi script.

Let's step until the end and see how our "signature" does:

```
btcdeb> step
		<> PUSH stack f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
script                                                           |                                                             stack
-----------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                      |   f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
                                                                 | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
#0001 OP_CHECKSIG
btcdeb>
GenericTransactionSignatureChecker::CheckSchnorrSignature(64 len sig, 32 len pubkey, sigversion=2)
  sig         = 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
  pub key     = f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
- schnorr sighash = bf775fc048a7693eee19e5f51f2160b7b4f52b640499cd2b9e46a4be17b51f1a
  pubkey.VerifySchnorrSignature(sig=000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f, sighash=bf775fc048a7693eee19e5f51f2160b7b4f52b640499cd2b9e46a4be17b51f1a):
  result: FAILURE
- schnorr signature verification ***FAILED***
error: unknown error

script                                                           |                                                             stack 
-----------------------------------------------------------------+-------------------------------------------------------------------
                                                                 |   f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
                                                                 | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
#0001 OP_CHECKSIG
```

OK yeah that didn't go too well. However, btcdeb has now given us a vital clue. The only one we need, in fact, to complete this transaction: the signature hash (abbreviate "sighash") -- it is `bf775fc048a7693eee19e5f51f2160b7b4f52b640499cd2b9e46a4be17b51f1a` (big endian, so we need to *reverse* it), and you can see it above a few lines above the "result: FAILURE" part. With that, and our privkey (which we created at the start) tweaked with that tweak we created, we can now create an *actual* signature!

```Bash
btcdeb> tf taproot-tweak-seckey 3bed2cb3a3acf7b6a8ef408420cc682d5520e26976d354254f528c965612054f 0b0e6981ce6cac74d055d0e4c25e5b4455a083b3217761327867f26460e0a776
(pubkey verified: 03f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c)
cf213cce2abfb4be27669060a191f315bb2e7e3059ecad48e8e7c45adb04e368
# we can verify that this is correct by using get-xpubkey and comparing this to our pubkey we made before
btcdeb> tf get-xpubkey cf213cce2abfb4be27669060a191f315bb2e7e3059ecad48e8e7c45adb04e368
(pk_parity = 1)
f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
btcdeb> tf sign_schnorr reverse(bf775fc048a7693eee19e5f51f2160b7b4f52b640499cd2b9e46a4be17b51f1a) cf213cce2abfb4be27669060a191f315bb2e7e3059ecad48e8e7c45adb04e368
b36beb8bf7bac92bd3b457a254476c1cf75059fbabc00eb64ccf4e6b462f41ad1dc24615e699bfa1287b82baffc42263bbefc4e2b6e8fc96e6f1fbe5adafcff1
```

We can now replace our `00010203...` thingie with the above and try again.

```Bash
$ btcdeb --verbose --txin=$txin --tx='020000000001 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b 01 40 b36beb8bf7bac92bd3b457a254476c1cf75059fbabc00eb64ccf4e6b462f41ad1dc24615e699bfa1287b82baffc42263bbefc4e2b6e8fc96e6f1fbe5adafcff1 00000000'
[...]
#0001 OP_CHECKSIG
btcdeb>
GenericTransactionSignatureChecker::CheckSchnorrSignature(64 len sig, 32 len pubkey, sigversion=2)
  sig         = b36beb8bf7bac92bd3b457a254476c1cf75059fbabc00eb64ccf4e6b462f41ad1dc24615e699bfa1287b82baffc42263bbefc4e2b6e8fc96e6f1fbe5adafcff1
  pub key     = f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
SignatureHashSchnorr(in_pos=0, hash_type=00)
- taproot sighash
- schnorr sighash = bf775fc048a7693eee19e5f51f2160b7b4f52b640499cd2b9e46a4be17b51f1a
  pubkey.VerifySchnorrSignature(sig=b36beb8bf7bac92bd3b457a254476c1cf75059fbabc00eb64ccf4e6b462f41ad1dc24615e699bfa1287b82baffc42263bbefc4e2b6e8fc96e6f1fbe5adafcff1, sighash=bf775fc048a7693eee19e5f51f2160b7b4f52b640499cd2b9e46a4be17b51f1a):
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
$ bcli testmempoolaccept '["020000000001015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b0140b36beb8bf7bac92bd3b457a254476c1cf75059fbabc00eb64ccf4e6b462f41ad1dc24615e699bfa1287b82baffc42263bbefc4e2b6e8fc96e6f1fbe5adafcff100000000"]'
[
  {
    "txid": "275f90dcfc8b6c81ea54ee6e7648b3f628ee411ef11d1fdaf9c0074b04dbfef9",
    "wtxid": "29d1864fa0105fac5fe08783b74051482e63007f11ffb21ed8fe9029aa27b9da",
    "allowed": true,
    "vsize": 99,
    "fees": {
      "base": 0.00001000
    }
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

> 020000000001 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b 02 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000

(Note that you can use the `prefix-compact-size` transform inside btcdeb to generate the size prefixed variants, e.g. `tf prefix-compact-size c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9` inside btcdeb gives `41c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9`.)

```Bash
$ btcdeb --verbose --txin=$txin --tx='020000000001 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b 02 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000'
btcdeb 0.4.22 -- type `btcdeb -h` for start up options
got segwit transaction 275f90dcfc8b6c81ea54ee6e7648b3f628ee411ef11d1fdaf9c0074b04dbfef9:
CTransaction(hash=275f90dcfc, ver=2, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(303d28a45a, 0), scriptSig=)
    CScriptWitness(a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac, c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9)
    CTxOut(nValue=0.00009000, scriptPubKey=0014976a249d6f98141981dc54c536)

got input tx #0 303d28a45ad1234fd8092df147ae52464a4b7de0d343a2d79dc28dd7611dd25a:
CTransaction(hash=303d28a45a, ver=2, vin.size=1, vout.size=2, nLockTime=202)
    CTxIn(COutPoint(7cdda95c72, 0), scriptSig=, nSequence=4294967294)
    CScriptWitness(30440220472c552bc77523659aad75aac0674c723c058b80484f5186769c03cb0287b52f02200b0e449a51f185017a64c1261c852e51c2cbb4fee949a50d634224dfb27d23f601, 0344de9257311c16349ff0acd2be071433e3a1de0169ed900ae3f2e81f0b3f37fc)
    CTxOut(nValue=0.00010000, scriptPubKey=5120f128a8a8a636e19f00a8016955)
    CTxOut(nValue=49.99918776, scriptPubKey=0014801addecfc3d8a646ad95a2d48)

input tx index = 0; tx input vout = 0; value = 10000
got witness stack of size 2
34 bytes (v0=P2WSH, v1=taproot/tapscript)
Taproot commitment:
- control  = c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
- program  = f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
- script   = a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
- path len = 1
- p        = 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5
- q        = f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
- k        = 423b94cec6e38364eda58e7825e582cb8ef75c13236e4191629cf2b432862c63          (tap leaf hash)
  (TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac))
valid script
- generating prevout hash from 1 ins
[+] COutPoint(303d28a45a, 0)
8 op script loaded. type `help` for usage information
script                                                             |                                                             stack 
-------------------------------------------------------------------+-------------------------------------------------------------------
<<< taproot commitment >>>                                         |                                                               i: 0
Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205f... | k: 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce94...
Tweak: 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662... | 
CheckTapTweak                                                      | 
<<< committed script >>>                                           | 
OP_SHA256                                                          | 
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   | 
OP_EQUALVERIFY                                                     | 
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   | 
OP_CHECKSIG                                                        | 
#0000 Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
```

The tapscript commitment succeeded. Yay! Now as you can see we still need to add the inputs that satisfy the script itself. We will be adding those on the left hand side of the program || control object blob in the witness. Generally speaking, tapscript spending witness stack looks like: `<argN> ... <arg2> <arg1> <script> <control object>`.

* Firstly, the preimage which, when hashed, turns into the above: 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
* Second, the signature for the script. We don't have one, yet, so let's just put 64 random bytes in and have btcdeb tell us the sighash.

Flipped around, since args are opposite order:

> 020000000001 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b 04 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 20 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000

```Bash
$ btcdeb --verbose --txin=$txin --tx='020000000001 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b 04 40 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 20 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000'
btcdeb 0.4.22 -- type `btcdeb -h` for start up options
LOG: signing segwit taproot
got segwit transaction 275f90dcfc8b6c81ea54ee6e7648b3f628ee411ef11d1fdaf9c0074b04dbfef9:
CTransaction(hash=275f90dcfc, ver=2, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(303d28a45a, 0), scriptSig=)
    CScriptWitness(000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f, 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f, a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac, c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9)
    CTxOut(nValue=0.00009000, scriptPubKey=0014976a249d6f98141981dc54c536)

got input tx #0 303d28a45ad1234fd8092df147ae52464a4b7de0d343a2d79dc28dd7611dd25a:
CTransaction(hash=303d28a45a, ver=2, vin.size=1, vout.size=2, nLockTime=202)
    CTxIn(COutPoint(7cdda95c72, 0), scriptSig=, nSequence=4294967294)
    CScriptWitness(30440220472c552bc77523659aad75aac0674c723c058b80484f5186769c03cb0287b52f02200b0e449a51f185017a64c1261c852e51c2cbb4fee949a50d634224dfb27d23f601, 0344de9257311c16349ff0acd2be071433e3a1de0169ed900ae3f2e81f0b3f37fc)
    CTxOut(nValue=0.00010000, scriptPubKey=5120f128a8a8a636e19f00a8016955)
    CTxOut(nValue=49.99918776, scriptPubKey=0014801addecfc3d8a646ad95a2d48)

input tx index = 0; tx input vout = 0; value = 10000
got witness stack of size 4
34 bytes (v0=P2WSH, v1=taproot/tapscript)
Taproot commitment:
- control  = c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
- program  = f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
- script   = a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
- path len = 1
- p        = 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5
- q        = f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c
- k        = 423b94cec6e38364eda58e7825e582cb8ef75c13236e4191629cf2b432862c63          (tap leaf hash)
  (TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac))
valid script
- generating prevout hash from 1 ins
[+] COutPoint(303d28a45a, 0)
8 op script loaded. type `help` for usage information
script                                                             |                                                             stack 
-------------------------------------------------------------------+-------------------------------------------------------------------
<<< taproot commitment >>>                                         |                                                               i: 0
Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205f... | k: 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce94...
Tweak: 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662... | 
CheckTapTweak                                                      | 
<<< committed script >>>                                           | 
OP_SHA256                                                          | 
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   | 
OP_EQUALVERIFY                                                     | 
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   | 
OP_CHECKSIG                                                        | 
#0000 Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
btcdeb> step
- looping over path (0..0)
  - 0: node = c8...; taproot control node match -> k first
  (TapBranch(TapLeaf(0xc0 || a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac) || Span<33,32>=c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9))
  - 0: k -> 6b9f0cd659a5c64f4f5ac4f84e7998dae7fec41b47f5d7da6da9e21f8c6f6441
script                                                             |                                                             stack 
-------------------------------------------------------------------+-------------------------------------------------------------------
<<< taproot commitment >>>                                         |                                                               i: 1
Branch: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205f... | k: 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c...
Tweak: 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662... | 
CheckTapTweak                                                      | 
<<< committed script >>>                                           | 
OP_SHA256                                                          | 
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   | 
OP_EQUALVERIFY                                                     | 
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   | 
OP_CHECKSIG                                                        | 
#0001 Tweak: 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5
btcdeb> 
- looping over path (0..0)
- q.CheckTapTweak(p, k, 1) == success
script                                                             |                                                             stack 
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_SHA256                                                          |   107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
OP_EQUALVERIFY                                                     | 
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   | 
OP_CHECKSIG                                                        | 
#0002 CheckTapTweak
btcdeb> 
		<> POP  stack
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                             |                                                             stack 
-------------------------------------------------------------------+-------------------------------------------------------------------
6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333   |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_EQUALVERIFY                                                     | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   | 
OP_CHECKSIG                                                        | 
#0003 OP_SHA256
btcdeb> 
		<> PUSH stack 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
script                                                             |                                                             stack 
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_EQUALVERIFY                                                     |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   |   6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
OP_CHECKSIG                                                        | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
#0004 6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333
btcdeb> 
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
		<> POP  stack
script                                                             |                                                             stack 
-------------------------------------------------------------------+-------------------------------------------------------------------
4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10   | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
OP_CHECKSIG                                                        | 
#0005 OP_EQUALVERIFY
btcdeb> 
		<> PUSH stack 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
script                                                             |                                                             stack 
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_CHECKSIG                                                        |   4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
                                                                   | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0...
#0006 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
btcdeb> 
EvalChecksig() sigversion=3
Eval Checksig Tapscript
- sig must not be empty: ok
- validation weight - 50 -> 235
- 32 byte pubkey (new type); schnorr sig check
GenericTransactionSignatureChecker::CheckSchnorrSignature(64 len sig, 32 len pubkey, sigversion=3)
  sig         = 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
  pub key     = 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
- schnorr sighash = 91ba37295ca0850de315113a9adac131e34266a02e56f73970c96c60f5db1ca9
  pubkey.VerifySchnorrSignature(sig=000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f, sighash=91ba37295ca0850de315113a9adac131e34266a02e56f73970c96c60f5db1ca9):
  result: FAILURE
- schnorr signature verification ***FAILED***
- schnorr sig check failed
error: Invalid Schnorr signature
btcdeb>
```

OK. The sighash is `91ba37295ca0850de315113a9adac131e34266a02e56f73970c96c60f5db1ca9`. We can sign it, since we have Bob's privkey `81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9`. Remember; sighash is a hash. We need to reverse it below.

```Bash
btcdeb> tf sign_schnorr reverse(91ba37295ca0850de315113a9adac131e34266a02e56f73970c96c60f5db1ca9) 81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9
b9e600c70ed8f4b934300077d49f5b6cbd3f4c9981a2a55ce2f7ef92758e1244b1b306d73227fa478012e0986502b729973594bb741915dcec5bae086b89a7cd
```

Now let's put the real signature in and try again.

> 020000000001 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b 04 40 b9e600c70ed8f4b934300077d49f5b6cbd3f4c9981a2a55ce2f7ef92758e1244b1b306d73227fa478012e0986502b729973594bb741915dcec5bae086b89a7cd 20 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000

```Bash
$ btcdeb --txin=$txin --tx='020000000001 015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b 04 40 b9e600c70ed8f4b934300077d49f5b6cbd3f4c9981a2a55ce2f7ef92758e1244b1b306d73227fa478012e0986502b729973594bb741915dcec5bae086b89a7cd 20 107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f 45 a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
41 c1 5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5 c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9 00000000'
[...]
#0006 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
btcdeb> 
EvalChecksig() sigversion=3
Eval Checksig Tapscript
- sig must not be empty: ok
- validation weight - 50 -> 235
- 32 byte pubkey (new type); schnorr sig check
GenericTransactionSignatureChecker::CheckSchnorrSignature(64 len sig, 32 len pubkey, sigversion=3)
  sig         = b9e600c70ed8f4b934300077d49f5b6cbd3f4c9981a2a55ce2f7ef92758e1244b1b306d73227fa478012e0986502b729973594bb741915dcec5bae086b89a7cd
  pub key     = 4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
SignatureHashSchnorr(in_pos=0, hash_type=00)
- tapscript sighash
- schnorr sighash = 91ba37295ca0850de315113a9adac131e34266a02e56f73970c96c60f5db1ca9
  pubkey.VerifySchnorrSignature(sig=b9e600c70ed8f4b934300077d49f5b6cbd3f4c9981a2a55ce2f7ef92758e1244b1b306d73227fa478012e0986502b729973594bb741915dcec5bae086b89a7cd, sighash=91ba37295ca0850de315113a9adac131e34266a02e56f73970c96c60f5db1ca9):
  result: success
		<> POP  stack
		<> POP  stack
		<> PUSH stack 01
script                                                             |                                                             stack 
-------------------------------------------------------------------+-------------------------------------------------------------------
                                                                   |                                                                 01
```

Success! Let's broadcast this one to the network:

```Bash
$ bcli sendrawtransaction 020000000001015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b0440b9e600c70ed8f4b934300077d49f5b6cbd3f4c9981a2a55ce2f7ef92758e1244b1b306d73227fa478012e0986502b729973594bb741915dcec5bae086b89a7cd20107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000
275f90dcfc8b6c81ea54ee6e7648b3f628ee411ef11d1fdaf9c0074b04dbfef9
$ bcli getrawtransaction 275f90dcfc8b6c81ea54ee6e7648b3f628ee411ef11d1fdaf9c0074b04dbfef9 1
{
  "txid": "275f90dcfc8b6c81ea54ee6e7648b3f628ee411ef11d1fdaf9c0074b04dbfef9",
  "hash": "06bd108659b259eb0113430e7014fe88bf081d4c2eb65486d551976a3fb4cb52",
  "version": 2,
  "size": 319,
  "vsize": 142,
  "weight": 565,
  "locktime": 0,
  "vin": [
    {
      "txid": "303d28a45ad1234fd8092df147ae52464a4b7de0d343a2d79dc28dd7611dd25a",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "b9e600c70ed8f4b934300077d49f5b6cbd3f4c9981a2a55ce2f7ef92758e1244b1b306d73227fa478012e0986502b729973594bb741915dcec5bae086b89a7cd",
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
        "asm": "0 976a249d6f98141981dc54c536fe19ec92b9975b",
        "hex": "0014976a249d6f98141981dc54c536fe19ec92b9975b",
        "address": "bcrt1qja4zf8t0nq2pnqwu2nzndlseajftn96m38eecx",
        "type": "witness_v0_keyhash"
      }
    }
  ],
  "hex": "020000000001015ad21d61d78dc29dd7a243d3e07d4b4a4652ae47f12d09d84f23d15aa4283d300000000000ffffffff012823000000000000160014976a249d6f98141981dc54c536fe19ec92b9975b0440b9e600c70ed8f4b934300077d49f5b6cbd3f4c9981a2a55ce2f7ef92758e1244b1b306d73227fa478012e0986502b729973594bb741915dcec5bae086b89a7cd20107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c15bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000"
}
```

And we're done! Hope it was helpful. Please submit pull requests or issues with improvements to this document and/or btcdeb.
