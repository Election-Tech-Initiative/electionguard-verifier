![Microsoft Defending Democracy Program: ElectionGuard](images/electionguard-banner.svg)

#  🗳️ ElectionGuard Verifier

![package](https://github.com/microsoft/electionguard-verifier/workflows/Publish/badge.svg)
[![license](https://img.shields.io/github/license/microsoft/electionguard-verifier)](License)

This repository contains a reference implementation of a verifier for the
encrypted record of an election. After an election is completed, the verifier
can be run to check that the published tally accords with the tally of all
encrypted ballots, yet without the need to decrypt any ballots. It does this by
verifying a variety of *zero knowledge proofs* that establish the integrity of
the encrypted election data.

The verifier checks the below properties about the encrypted election record,
the totality of which is sufficient to ensure that the record corresponds to a
correct representation of the election which generated the published final
tally. Properties established via zero-knowledge proof are emphasized.

- For the **entire election**, we check:
  + The number of trustees who can together decrypt the election is greater than
    zero
  + The threshold of trustees necessary to decrypt the election is greater than
    zero
  + The threshold of trustees necessary to decrypt the election is not greater
    than the total number of trustees
  + The encryption parameters of the election (prime modulus and group
    generator) are valid
  + The hash of the election parameters was computed correctly
  + The "extended base hash" was computed correctly
  + The joint public key was computed correctly
- For the **election trustees**, we check:
  + The number of trustee public keys is equal to the number of trustees
  + Each trustee public key has the correct number of coefficients necessary to
    implement the threshold decryption specified in the election parameters
  + *Each trustee has possession of a private key corresponding to the public
    key they published*
- For each **cast ballot**, we check:
  + The number of contests is equal to the number of contests specified for the
    election
  + The number of possible selections for each contest is equal to the number of
    possible selections specified for the election
  + *For each contest, the voter selected no more than the total permissible
    number of selections for that contest*
  + *For each contest, any given selection corresponds to either one or zero
    votes (that is, no numerical trickery was used to manufacture a ballot that
    "counts twice")*
- For each **spoiled ballot**, we check:
  + The number of contests is equal to the number of contests specified for the
    election
  + The number of possible selections for each contest is equal to the number of
    possible selections specified for the election
  + The encrypted ballot decrypts to the cleartext ballot that accompanies it
  + *An assortment of other validity and well-formedness checks [TODO: expand on
    this]*
- For the **published final tally**, we check:
  + The encrypted sum we calculated from the individual ballots matches the
    encrypted sum published in the election record
  + *The encrypted sum published is an encryption of the published cleartext
    result of the election*

## The Role of This Implementation


This implementation is meant to be a **reference implementation** of the
verifier -- it is meant to be simple, comprehensible, and correct. While we would
like it to be efficient and scalable, these concerns are secondary to its role
as a reference. As a result, places in this codebase which are difficult to
understand or under-documented should be considered bugs -- please report them in
the issue tracker if you find them.

## Building and Running

This project is a Rust project and can be built using the standard Rust
toolchain. Because of the high quantity of big-integer arithmetic in critical
sections of the code, it's necessary for decent performance to build in release
mode:

```
$ cargo build --release
```

There are two executables bundled with this crate: `verify` and `encrypt`. The
former is the tool described above, and can be run like:

```
$ cargo run --release --bin verify -- -i $PATH_TO_ELECTION_RECORD.json
```

If not given a path via `-i` (or equivalently `--input`) the verifier will
expect to read the record from stdin.

The `encrypt` tool is predominantly useful for testcase generation. It merely
reads an unencrypted election record file on stdin and outputs an encrypted
election record file on stdout, encrypted using randomly-generated trustee keys.
For example:

```
$ cat $UNENCRYPTED_RECORD.json | cargo run --release --bin encrypt > $ENCRYPTED_RECORD.json
```

The `tests/` directory contains a variety of files generated using this tool. At
present, they are:

- `invalid_randomized.json`: randomly generated numbers for all data, which
  should fail every single check
- `invalid_three_different_broken_proofs`: a valid election encryption except
  for three arbitrary proofs which have been altered by a single-digit change
- `valid_encrypted.json`: a valid election encryption
- `unencrypted.json`: a small sample unencrypted election record demonstrating
  the schema expected by the `encrypt` tool and suitable for generating test
  cases like the above

## Contributing
Help defend democracy and **[contribute to the project][]**.

[Code of Conduct]: CODE_OF_CONDUCT.md
[Contribute to the project]: CONTRIBUTING.md