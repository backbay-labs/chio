package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/backbay-labs/chio/sdks/go/chio-go/invariants"
	"os"
)

func run() error {
	trust := flag.String("trusted-signers", "trusted-signers.json", "JSON array of independently selected trusted public keys")
	flag.Parse()
	receiptPath := "fixtures/minimal-evidence/receipts.ndjson"
	if flag.NArg() > 0 {
		receiptPath = flag.Arg(0)
	}
	keys, err := os.ReadFile(*trust)
	if err != nil {
		return err
	}
	var signers []string
	if err := json.Unmarshal(keys, &signers); err != nil {
		return err
	}
	if len(signers) == 0 {
		return fmt.Errorf("trusted signer set is empty")
	}
	f, err := os.Open(receiptPath)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	count := 0
	valid := true
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return err
		}
		receipt, ok := record["receipt"].(map[string]any)
		if !ok {
			receipt = record
		}
		result, err := invariants.VerifyReceiptWithTrustedSigners(receipt, signers)
		if err != nil {
			return err
		}
		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		valid = valid && result.Ok
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count == 0 || !valid {
		return fmt.Errorf("receipt verification failed")
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
