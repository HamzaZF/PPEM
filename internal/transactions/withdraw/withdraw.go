package withdraw

import (
	"bytes"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

type Note struct {
	Coins  *big.Int
	Energy *big.Int
	Pk     *big.Int
	Rho    *big.Int
	R      *big.Int
	Cm     *big.Int
}

type WithdrawTx struct {
	SnIn      *big.Int
	CmOut     *big.Int
	PkT       sw_bls12377.G1Affine
	CipherAux [3]*big.Int
}

// PRFGo implements the serial number PRF using MiMC (Go version)
func PRFGo(sk, rho *big.Int) *big.Int {
	h := mimc.NewMiMC()
	h.Write(sk.Bytes())
	h.Write(rho.Bytes())
	return new(big.Int).SetBytes(h.Sum(nil))
}

// BuildWithdrawWitness constructs the witness for CircuitWithdraw
func BuildWithdrawWitness(nIn Note, skIn *big.Int, nOut Note, pkT sw_bls12377.G1Affine, cipherAux [3]*big.Int, bid *big.Int) *CircuitWithdraw {
	w := &CircuitWithdraw{}
	w.SnIn = PRFGo(skIn, nIn.Rho)
	w.CmOut = nOut.Cm
	w.PkT = pkT
	for i := 0; i < 3; i++ {
		w.CipherAux[i] = cipherAux[i]
	}
	w.SkIn = skIn
	w.Bid = bid // bid value is required for Algorithm 4
	w.NIn.Coins = nIn.Coins
	w.NIn.Energy = nIn.Energy
	w.NIn.PkIn = nIn.Pk
	w.NIn.RhoIn = nIn.Rho
	w.NIn.RIn = nIn.R
	w.NIn.CmIn = nIn.Cm
	w.NOut.Coins = nOut.Coins
	w.NOut.Energy = nOut.Energy
	w.NOut.PkOut = nOut.Pk
	w.NOut.RhoOut = nOut.Rho
	w.NOut.ROut = nOut.R
	w.NOut.CmOut = nOut.Cm
	return w
}

// Withdraw runs the withdrawal protocol, returns tx and proof
func Withdraw(
	nIn Note, skIn *big.Int, nOut Note, pkT sw_bls12377.G1Affine, cipherAux [3]*big.Int, bid *big.Int,
	pk groth16.ProvingKey, ccs constraint.ConstraintSystem,
) (*WithdrawTx, []byte, error) {
	witness := BuildWithdrawWitness(nIn, skIn, nOut, pkT, cipherAux, bid)
	gnarkWitness, err := frontend.NewWitness(witness, nil)
	if err != nil {
		return nil, nil, err
	}
	proof, err := groth16.Prove(ccs, pk, gnarkWitness)
	if err != nil {
		return nil, nil, err
	}
	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, nil, err
	}
	// Convert frontend.Variable to *big.Int for SnIn and CmOut
	snInStr, _ := witness.SnIn.(string)
	cmOutStr, _ := witness.CmOut.(string)
	snIn := new(big.Int)
	cmOut := new(big.Int)
	snIn.SetString(snInStr, 10)
	cmOut.SetString(cmOutStr, 10)
	tx := &WithdrawTx{
		SnIn:      snIn,
		CmOut:     cmOut,
		PkT:       witness.PkT,
		CipherAux: cipherAux,
	}
	return tx, proofBuf.Bytes(), nil
}

// VerifyWithdraw verifies a withdrawal transaction and its proof
func VerifyWithdraw(tx *WithdrawTx, proofBytes []byte, vk groth16.VerifyingKey) error {
	// Create public witness
	publicWitness := &CircuitWithdraw{
		SnIn:  tx.SnIn.String(),
		CmOut: tx.CmOut.String(),
		PkT:   tx.PkT,
		CipherAux: [3]frontend.Variable{
			tx.CipherAux[0].String(),
			tx.CipherAux[1].String(),
			tx.CipherAux[2].String(),
		},
	}

	// Create gnark public witness
	w, err := frontend.NewWitness(publicWitness, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}

	// Unmarshal proof
	proof := groth16.NewProof(ecc.BW6_761)
	_, err = proof.ReadFrom(bytes.NewReader(proofBytes))
	if err != nil {
		return err
	}

	// Verify the proof
	return groth16.Verify(proof, vk, w)
}
