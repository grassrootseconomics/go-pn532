package pn532

import (
	"errors"
	"fmt"
	"time"
)

const (
	maxSectors = uint8(16)
	maxBlocks  = uint8(64)
)

var (
	// Usual factory key
	fKey = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	// MAD key for sector 0
	mKey = []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}
	// NDEF key
	nKey = []byte{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}
	// 0 key
	zeroKey = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	// Common access control bits for headers and trailers
	bT0 = []byte{0x78, 0x77, 0x88, 0xC1}
	btN = []byte{0x7F, 0x07, 0x88, 0x40}

	// Fixed block data for sector 0
	b1 = []byte{0x0F, 0x00, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1}
	b2 = []byte{0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1}
	b3 = []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x78, 0x77, 0x88, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	// Fixed block header (only when formatting)
	bnH = []byte{0x03, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// Fixed block trailer
	bn = []byte{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0x7F, 0x07, 0x88, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
)

// IsNDEFFormatted checks if the tag is NDEF formatted with the default NDEF KeyA
func (t *MIFARETag) IsNDEFFormatted() bool {
	ndefKeyBytes := []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}
	defer clear(ndefKeyBytes)

	return t.Authenticate(0, MIFAREKeyA, ndefKeyBytes) == nil
}

// FormatForNDEF formats the tag for NDEF with the default NDEF KeyA
// This should take about 2 seconds which is also the time most apps take
func (t *MIFARETag) FormatForNDEF() error {
	if err := t.AuthenticateRobust(0, MIFAREKeyA, fKey); err != nil {
		return fmt.Errorf("failed to authenticate sector 0: %w", err)
	}
	if err := t.WriteBlock(1, b1); err != nil {
		return fmt.Errorf("failed to write block %d error: %w", 1, err)
	}
	if err := t.WriteBlock(2, b2); err != nil {
		return fmt.Errorf("failed to write block %d error: %w", 2, err)
	}

	if err := t.WriteBlock(3, b3); err != nil {
		return fmt.Errorf("failed to write block %d error: %w", 3, err)
	}

	for sector := uint8(1); sector < maxSectors; sector++ {
		if err := t.AuthenticateRobust(sector, MIFAREKeyA, fKey); err != nil {
			continue
		}

		headerBlock := sector * 4
		if err := t.WriteBlock(headerBlock, bnH); err != nil {
			return fmt.Errorf("failed to write block %d error: %w", headerBlock, err)
		}

		trailerBlock := sector*4 + 3
		if err := t.WriteBlock(trailerBlock, bn); err != nil {
			return fmt.Errorf("failed to write block %d error: %w", trailerBlock, err)
		}
	}

	time.Sleep(t.config.HardwareDelay)
	return nil
}

// authenticateForNDEFAlternative checks if the tag is NDEF formatted with the schema described in FormatForNDEF
func (t *MIFARETag) authenticateForNDEFAlternative() (*authenticationResult, error) {
	result := &authenticationResult{}

	err := t.AuthenticateRobust(1, MIFAREKeyA, nKey)
	if err == nil {
		result.isNDEFFormatted = true
		return result, nil
	}

	return result, nil
}

// WriteNDEFAlternative writes an NDEF message to the tag, formatting it if necessary
// WARNING: This is handwritten for a specific use case where time and write performance is critical
func (t *MIFARETag) WriteNDEFAlternative(message *NDEFMessage) error {
	if len(message.Records) == 0 {
		return errors.New("no NDEF records to write")
	}

	data, err := BuildNDEFMessageEx(message.Records)
	if err != nil {
		return fmt.Errorf("failed to build NDEF message: %w", err)
	}

	_, err = t.authenticateForNDEFAlternative()
	if err != nil {
		return err
	}

	// Skip validation because we know our size
	if err := t.writeNDEFDataAlternative(data); err != nil {
		return err
	}

	// We don't clear blocks because we have formatted with a special scheme above
	return nil
}

func (t *MIFARETag) writeNDEFDataAlternative(data []byte) error {
	block := uint8(4)
	for i := 0; i < len(data); i += mifareBlockSize {
		if block%4 == 3 {
			block++
		}

		if block >= maxBlocks {
			return errors.New("NDEF data exceeds tag capacity")
		}

		if err := t.writeDataBlockAlternative(block, data, i); err != nil {
			return err
		}
		block++
	}
	return nil
}

func (t *MIFARETag) writeDataBlockAlternative(block uint8, data []byte, offset int) error {
	end := offset + mifareBlockSize
	if end > len(data) {
		blockData := make([]byte, mifareBlockSize)
		copy(blockData, data[offset:])
		return t.writeBlockWithErrorAlternative(block, blockData)
	}
	return t.writeBlockWithErrorAlternative(block, data[offset:end])
}

func (t *MIFARETag) writeBlockWithErrorAlternative(block uint8, data []byte) error {
	if err := t.WriteBlockAutoAlternative(block, data); err != nil {
		return fmt.Errorf("failed to write block %d: %w", block, err)
	}
	return nil
}

func (t *MIFARETag) WriteBlockAutoAlternative(block uint8, data []byte) error {
	sector := block / mifareSectorSize

	// Check if we need to authenticate
	if t.lastAuthSector != int(sector) {
		// For write operations, typically Key B is required (but this depends on access bits)
		// Try Key B first, then Key A
		err := t.authenticateNDEFAlternative(sector, MIFAREKeyB)
		if err != nil {
			// Try Key A
			err = t.authenticateNDEFAlternative(sector, MIFAREKeyA)
			if err != nil {
				return fmt.Errorf("failed to authenticate to sector %d: %w", sector, err)
			}
		}
	}

	return t.WriteBlock(block, data)
}

func (t *MIFARETag) authenticateNDEFAlternative(sector uint8, keyType byte) error {
	// Because we know the standard NDEF layout we can perform some shortcuts cutting down auth time.
	switch keyType {
	case MIFAREKeyA:
		return t.AuthenticateRobust(sector, keyType, nKey)
	case MIFAREKeyB:
		return t.AuthenticateRobust(sector, keyType, fKey)
	}
	return nil
}
