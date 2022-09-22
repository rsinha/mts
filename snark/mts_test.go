
package mts

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

const NUM_NODES = 200

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKeys [NUM_NODES]PublicKey `gnark:",public"`
	Signatures [NUM_NODES]Signature `gnark:",public"`
	Message   frontend.Variable 	`gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return Verify(curve, circuit.Signatures, circuit.Message, circuit.PublicKeys, &mimc)
}

func TestEddsa(t *testing.T) {

	assert := test.NewAssert(t)

	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	conf := testData{hash.MIMC_BLS12_381, tedwards.BLS12_381}

	seed := time.Now().Unix()
	t.Logf("setting seed in rand %d", seed)
	randomness := rand.New(rand.NewSource(seed))

	var privKeys [NUM_NODES]signature.Signer;

	snarkCurve, err := twistededwards.GetSnarkCurve(conf.curve)
	assert.NoError(err)

	// pick a message to sign
	var msg big.Int
	msg.Rand(randomness, snarkCurve.Info().Fr.Modulus())
	t.Log("msg to sign", msg.String())
	msgData := msg.Bytes()

	// create and compile the circuit for signature verification
	var circuit eddsaCircuit
	
	var witness eddsaCircuit
	witness.Message = msg

	circuit.curveID = conf.curve

	for i := 0; i < NUM_NODES; i++ {
		// generate parameters for the signatures
		privKey, err := eddsa.New(conf.curve, randomness)
		assert.NoError(err, "generating eddsa key pair")
		privKeys[i] = privKey

		// generate signature
		signature, err := privKey.Sign(msgData[:], conf.hash.New())
		assert.NoError(err, "signing message")

		// check if there is no problem in the signature
		pubKey := privKey.Public()
		checkSig, err := pubKey.Verify(signature, msgData[:], conf.hash.New())
		assert.NoError(err, "verifying signature")
		assert.True(checkSig, "signature verification failed")

		t.Log("verifying with correct signature")

		witness.PublicKeys[i].Assign(snarkCurve, pubKey.Bytes())
		witness.Signatures[i].Assign(snarkCurve, signature)

	}


	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(snarkCurve))

}
