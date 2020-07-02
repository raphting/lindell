package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	mathRand "math/rand"
)

func main() {
	numberParticipants := 4

	// Generate n public/private key pairs
	pubs, privs, err := genKeyPairs(numberParticipants)
	if err != nil {
		fmt.Printf("generating key pairs: %s", err.Error())
		return
	}

	// Protocol step 1
	// Generate a random string w
	w := make([]byte, 8)
	_, err = rand.Read(w)
	if err != nil {
		fmt.Printf("generating random w: %s", err.Error())
		return
	}
	// add magic bytes to identify correct w on client side
	w = append([]byte("li"), w...)
	fmt.Printf("Server random string w: %x\n", w)

	// For every participant, generate a random coin
	coins := make([][]byte, numberParticipants)
	for i := 0; i < numberParticipants; i++ {
		c := make([]byte, 8)
		_, err = rand.Read(c)
		if err != nil {
			fmt.Printf("generating random coin: %s", err.Error())
			return
		}
		coins[i] = c
	}

	// Encrypt w with coin for every public key
	encMessages, err := encrypt(pubs, w, coins)
	if err != nil {
		fmt.Printf("encrypt w and coin: %s\n", err.Error())
		return
	}

	// Protocol step 2
	// prepare client
	c := client{
		allPublicKeys: pubs,
		privateKey:    privs[mathRand.Intn(numberParticipants)], // Choose random participant to proof anonymity
		encMessages:   encMessages,
	}

	wDash, err := c.decrypt()
	if err != nil {
		fmt.Printf("client-side decrypt: %s\n", err.Error())
		return
	}
	fmt.Printf("Client w': %x\n", wDash)

	// Protocol step 3
	// compare w and wDash
	if !bytes.Equal(w, wDash) {
		fmt.Println("Access denied")
		return
	}
	fmt.Println("Access granted")

	// Protocol step 4
	// Verify server did not cheat on client
	// insert the following code snippet to pretend a cheat
	// coins[0] = []byte("cheat")
	err = c.verify(coins)
	if err != nil {
		fmt.Printf("client verification: %s\n", err.Error())
		return
	}
	fmt.Println("Verification successful")
}

type client struct {
	allPublicKeys []*[32]byte
	privateKey    *[32]byte
	encMessages   [][]byte
	wDash         []byte
}

func genKeyPairs(n int) ([]*[32]byte, []*[32]byte, error) {
	pubOut := make([]*[32]byte, n)
	privOut := make([]*[32]byte, n)
	for i := 0; i < n; i++ {
		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pubOut[i] = pub
		privOut[i] = priv
	}
	return pubOut, privOut, nil
}

func encrypt(pubs []*[32]byte, w []byte, coins [][]byte) ([][]byte, error) {
	if len(pubs) != len(coins) {
		return nil, errors.New("length public keys and coins do not match")
	}

	out := make([][]byte, len(pubs))
	for cnt, p := range pubs {
		enc, err := box.SealAnonymous(nil, append(w, coins[cnt]...), p, newDetermRand([]byte("deterministic")))
		if err != nil {
			return nil, err
		}
		out[cnt] = enc
	}

	return out, nil
}

func (c *client) decrypt() ([]byte, error) {
	if len(c.allPublicKeys) != len(c.encMessages) {
		return nil, errors.New("length of public keys and encrypted messages do not match")
	}

	for cnt, p := range c.allPublicKeys {
		decrypted, ok := box.OpenAnonymous(nil, c.encMessages[cnt], p, c.privateKey)
		if !ok {
			continue
		}
		// Verify magic byte
		if bytes.HasPrefix(decrypted, []byte("li")) {
			c.wDash = decrypted[:10]
			return decrypted[:10], nil
		}
	}

	return nil, errors.New("decryption not possible")
}

func (c client) verify(coins [][]byte) error {
	if len(c.allPublicKeys) != len(coins) || len(coins) != len(c.encMessages) {
		return errors.New("length of public keys, encrypted messages and coins does not match")
	}

	for cnt, p := range c.allPublicKeys {
		enc, err := box.SealAnonymous(nil, append(c.wDash, coins[cnt]...), p, newDetermRand([]byte("deterministic")))
		if err != nil {
			return err
		}
		if !bytes.Equal(enc, c.encMessages[cnt]) {
			fmt.Println("CHEAT")
			return errors.New("it appears the server cheated on us")
			// The server could de-anonymize us by putting a different w for every encrypted message.
			// By sending back our personalized w, the server knows our public key and hence our identity.
			// To verify the server did not cheat, check that all encrypted messages contain the same value for w.
		}
	}
	return nil
}

// As suggested by jpillora https://gist.github.com/jpillora/5a0471b246d541b984ab
func newDetermRand(seed []byte) io.Reader {
	return &determRand{next: seed}
}

type determRand struct {
	next []byte
}

func (d *determRand) cycle() []byte {
	result := sha512.Sum512(d.next)
	d.next = result[:sha512.Size/2]
	return result[sha512.Size/2:]
}

func (d *determRand) Read(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		out := d.cycle()
		n += copy(b[n:], out)
	}
	return n, nil
}
