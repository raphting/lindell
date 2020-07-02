Anonymous Authentication
========================

This software implements the anonymous authentication as described by Lindell, page 12
(https://www.blackhat.com/presentations/bh-usa-07/Lindell/Whitepaper/bh-usa-07-lindell-WP.pdf).

It uses the well known NaCl library for public key cryptography. To verify the client's anonymity in step 4,
the cypher text must be deterministic. For this reason, a deterministic random number generator is used.

## What's the use?

Please refer to above paper to get an overview of what anonymous authentication is.
