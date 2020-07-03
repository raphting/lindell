Anonymous Authentication
========================

This software implements the anonymous authentication as described by Lindell, page 12
(https://www.blackhat.com/presentations/bh-usa-07/Lindell/Whitepaper/bh-usa-07-lindell-WP.pdf).

It uses the well known NaCl library for public key cryptography. To verify the client's anonymity in step 4,
the cypher text must be deterministic. For this reason, a deterministic random number generator is used.

## What's the use?

Please refer to above paper to get an overview of what anonymous authentication is.

## Additional thoughts

* The list of public keys has to be public and accepted by all participants. Otherwise, the server could guess who is
about to authenticate, only encrypt with the victim's public key and send rubbish otherwise. If the victim sends back a
successful w, the server knows for sure it comes from the victim that he thought would try to authenticate.

* The paper suggests verifying the coins in step 4. In my opinion, the server could send all coins together with the
cypher text in step 2. In that way, once the client decrypted w, the client can verify the challenge right away, and
only on successful verification send back w to the server without risking being de-anonymized in step 3.
