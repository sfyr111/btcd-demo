package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	// Provided PSBT with one P2PKH input. Created in part 1 below.
	psbtBase64 = "cHNidP8BAFIBAAAAAX7Mj1abZbFtfUYFYBIFRKxCOxs8wfMRu3NhVBHTbnFfAQAAAAAAAAAAAayEAQAAAAAAFgAU8yFPpRndMpAJ7aO+RtRN4Nh3mbYAAAAAAAEBH6CGAQAAAAAAFgAUJw/E3xSMUU+8VVGHXk7Dc4vGNjkiBgOoVLKI2rj2DMlswSDkSf0KR7jQHULLPOWS/x3q8b3MqQyj8e/WAAAAAAMAAAAAAA=="

	// Extended Private Key.
	extPrivateKeyStr = "vprv9GpFMh8VMAXKgdZVFGXFvsexjr25MHKvtCY7vKHbRr8A6xCm4bQYbQrJmLz6h3F9MGf5edwxQuZR7DCLFVvjMxgfJ9so9mcN2SHGR3QFr3S"
)

// Part 1: Creating the PSBT (will be returned as base64)
func part1() string {
	// The extended private key was generated with Electrum and we derive the
	// specific key used.
	// `keyC` contains the private key that _contains_ the coins to be spend.
	keyC, _ := hdkeychain.NewKeyFromString(extPrivateKeyStr)
	fingerprint := keyC.ParentFingerprint()
	keyC, _ = keyC.Derive(0)
	keyC, _ = keyC.Derive(3) // Electrum derivation of the 4th address.
	pubKeyC, _ := keyC.ECPubKey()

	// Create a brand new PSBT spending the following outpoint.
	txhash, _ := chainhash.NewHashFromStr("5f716ed311546173bb11f3c13c1b3b42ac4405126005467d6db1659b568fcc7e")
	outpoint := wire.NewOutPoint(txhash, 1)
	inputs := []*wire.OutPoint{outpoint}
	pubkeyScript, _ := hex.DecodeString("0014270fc4df148c514fbc5551875e4ec3738bc63639")
	spendTxOut := wire.NewTxOut(100000, pubkeyScript)

	// The address and amount to send funds to.
	outAddress, err := btcutil.DecodeAddress("tb1q7vs5lfgem5efqz0d5wlyd4zdurv80xdkfkf3cn", &chaincfg.TestNet3Params)
	// The witnessScript consists of a `0x00`, followed by the size of the
	// pubkey-hash `0x20` and the pubkey-hash itself.
	witnessScript := append([]byte{0, 20}, outAddress.ScriptAddress()...)
	outputs := []*wire.TxOut{wire.NewTxOut(99500, witnessScript)}

	// Create the psbt instance.
	pC, err := psbt.New(inputs, outputs, wire.TxVersion, 0, []uint32{0}) // Note: typically the sequence is `0xffffffff`!
	if err != nil {
		panic(err)
	}

	// Use the Updater to add information to the input.
	u, err := psbt.NewUpdater(pC)
	if err != nil {
		panic(err)
	}

	u.AddInBip32Derivation(fingerprint, []uint32{0, 3}, pubKeyC.SerializeCompressed(), 0)
	u.AddInWitnessUtxo(spendTxOut, 0)
	u.AddInSighashType(0, 0)

	// Show the base64 encoding of the unsigned PSBT.
	b64, _ := pC.B64Encode()
	return b64

}

// Part 2: Sign the PSBT in base64 encoding and return it.
func part2(psbtBase64 string) string {
	// Reader for the PSBT.
	psbtBytes := []byte(psbtBase64)
	r := bytes.NewReader(psbtBytes)

	// Create instance of a PSBT.
	p, err := psbt.NewFromRawBytes(r, true)
	if err != nil {
		panic(err)
	}

	// Load the extended private key.
	bip32Key, err := hdkeychain.NewKeyFromString(extPrivateKeyStr)
	if err != nil {
		panic(err)
	}

	// Derivation path should be read from PSBT.
	// Note: We ignore checking the fingerprint, etc.
	path := p.Inputs[0].Bip32Derivation[0]
	for _, d := range path.Bip32Path {
		bip32Key, _ = bip32Key.Derive(d)
	}

	pubKey, err := bip32Key.ECPubKey()
	if err != nil {
		panic(err)
	}

	privKey, err := bip32Key.ECPrivKey()
	if err != nil {
		panic(err)
	}

	prevOuts := make(map[wire.OutPoint]*wire.TxOut)

	for i, input := range p.Inputs {
		if input.WitnessUtxo != nil {
			prevOuts[p.UnsignedTx.TxIn[i].PreviousOutPoint] = input.WitnessUtxo
		} else {
			panic("Missing WitnessUtxo in PSBT input")
		}
	}

	prevOutFetcher := txscript.NewMultiPrevOutFetcher(prevOuts)

	// Manually creating the signature.
	sigHashes := txscript.NewTxSigHashes(p.UnsignedTx, prevOutFetcher)
	sig, err := txscript.RawTxInWitnessSignature(p.UnsignedTx, sigHashes, 0,
		p.Inputs[0].WitnessUtxo.Value, p.Inputs[0].WitnessUtxo.PkScript,
		txscript.SigHashAll, privKey)

	// Use the Updater to add the signature to the input.
	u, err := psbt.NewUpdater(p)
	if err != nil {
		panic(err)
	}
	sucess, err := u.Sign(0, sig, pubKey.SerializeCompressed(), nil, nil)
	if err != nil {
		panic(err)
	}
	if sucess != psbt.SignSuccesful {
		panic("could not sucessfully sign for some reason")
	}

	// Finalize PSBT.
	err = psbt.Finalize(p, 0)
	tx, err := psbt.Extract(p)

	var buf bytes.Buffer
	tx.Serialize(&buf)
	return hex.EncodeToString(buf.Bytes())
}

func main() {
	fmt.Println("Base64 PSBT: ", part1())

	fmt.Println("Signed tx: ", part2(psbtBase64))
}
