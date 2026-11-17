// Package appleauth implements Apple GrandSlam SRP-6a authentication, 2FA,
// app token retrieval, and Anisette v3 provisioning/header requests in pure Go.
package appleauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// RFC 5054 2048-bit MODP group for Apple GrandSlam SRP-6a.
const rfc5054G2048Hex = "" +
	"ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050" +
	"a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50" +
	"e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b8" +
	"55f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773b" +
	"ca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748" +
	"544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6" +
	"af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb6" +
	"94b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73"

var (
	srpG2048N = mustBigIntHex(rfc5054G2048Hex)
	srpG2048G = big.NewInt(2)
)

func mustBigIntHex(s string) *big.Int {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(b)
}

type srpClient struct {
	n           *big.Int
	g           *big.Int
	nBytes      int
	newHash     func() hash.Hash
	usernameInX bool
}

func newAppleGSASRPClient() *srpClient {
	return &srpClient{
		n:           new(big.Int).Set(srpG2048N),
		g:           new(big.Int).Set(srpG2048G),
		nBytes:      (srpG2048N.BitLen() + 7) / 8,
		newHash:     sha256.New,
		usernameInX: false,
	}
}

type srpVerifier struct {
	m1         []byte
	m2         []byte
	sessionKey []byte
}

func (c *srpClient) randomSecret(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *srpClient) computePublicEphemeral(a []byte) []byte {
	aInt := new(big.Int).SetBytes(a)
	return new(big.Int).Exp(c.g, aInt, c.n).Bytes()
}

func padTo(b []byte, size int) []byte {
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func (c *srpClient) hashBytes(parts ...[]byte) []byte {
	h := c.newHash()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func (c *srpClient) computeU(aPub, bPub []byte) *big.Int {
	digest := c.hashBytes(padTo(aPub, c.nBytes), padTo(bPub, c.nBytes))
	return new(big.Int).SetBytes(digest)
}

func (c *srpClient) computeK() *big.Int {
	nBytes := padTo(c.n.Bytes(), c.nBytes)
	gBytes := padTo(c.g.Bytes(), c.nBytes)
	return new(big.Int).SetBytes(c.hashBytes(nBytes, gBytes))
}

func (c *srpClient) computeX(username, password, salt []byte) *big.Int {
	idUser := username
	if !c.usernameInX {
		idUser = nil
	}
	identityHash := c.hashBytes(idUser, []byte(":"), password)
	return new(big.Int).SetBytes(c.hashBytes(salt, identityHash))
}

func (c *srpClient) processReply(aBytes, username, password, salt, bPubBytes []byte) (*srpVerifier, error) {
	a := new(big.Int).SetBytes(aBytes)
	aPubBytes := c.computePublicEphemeral(aBytes)
	bPub := new(big.Int).SetBytes(bPubBytes)

	if new(big.Int).Mod(bPub, c.n).Sign() == 0 {
		return nil, errors.New("appleauth: invalid server ephemeral B")
	}

	u := c.computeU(aPubBytes, bPubBytes)
	k := c.computeK()
	x := c.computeX(username, password, salt)

	// S = (B - k * g^x) ^ (a + u * x) mod N
	gx := new(big.Int).Exp(c.g, x, c.n)
	kgx := new(big.Int).Mod(new(big.Int).Mul(k, gx), c.n)
	base := new(big.Int).Sub(bPub, kgx)
	base.Mod(base, c.n)
	if base.Sign() < 0 {
		base.Add(base, c.n)
	}
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	premaster := new(big.Int).Exp(base, exp, c.n).Bytes()

	sessionKey := c.hashBytes(premaster)

	nHash := c.hashBytes(padTo(c.n.Bytes(), c.nBytes))
	gHash := c.hashBytes(padTo(c.g.Bytes(), c.nBytes))
	xorNG := make([]byte, len(nHash))
	for i := range xorNG {
		xorNG[i] = nHash[i] ^ gHash[i]
	}
	userHash := c.hashBytes(username)

	m1 := c.hashBytes(xorNG, userHash, salt, aPubBytes, bPubBytes, sessionKey)
	m2 := c.hashBytes(aPubBytes, m1, sessionKey)

	return &srpVerifier{
		m1:         m1,
		m2:         m2,
		sessionKey: sessionKey,
	}, nil
}

func (v *srpVerifier) verifyServer(replyM2 []byte) error {
	if len(replyM2) != len(v.m2) || subtle.ConstantTimeCompare(v.m2, replyM2) != 1 {
		return fmt.Errorf("appleauth: server SRP proof mismatch")
	}
	return nil
}

func (v *srpVerifier) hmacSessionKey(label string) []byte {
	mac := hmac.New(sha256.New, v.sessionKey)
	_, _ = mac.Write([]byte(label))
	return mac.Sum(nil)
}
