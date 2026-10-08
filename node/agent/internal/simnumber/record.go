// Package simnumber reads the subscriber number from EF_MSISDN. It never
// writes the SIM, changes provisioning, or starts/resets the modem.
package simnumber

import (
	"encoding/hex"
	"errors"
	"strings"
)

// DecodeRecord accepts the ADN layout shared by SIM and USIM EF_MSISDN:
// an alpha identifier followed by the 14-byte number trailer.
func DecodeRecord(record []byte) (string, error) {
	if len(record) < 14 || len(record) > 255 {
		return "", errors.New("invalid MSISDN record size")
	}
	b := record[len(record)-14:]
	if b[0] == 0xff || b[0] == 0 {
		return "", nil
	}
	if b[0] < 2 || b[0] > 11 || b[1]&0x80 == 0 || b[1]&0x0f != 1 {
		return "", errors.New("invalid MSISDN number header")
	}
	// Extension records need their own verified decoder; never truncate a number.
	if b[13] != 0xff {
		return "", errors.New("MSISDN extension unsupported")
	}
	var digits strings.Builder
	filler := false
	for _, value := range b[2 : 1+int(b[0])] {
		for _, nibble := range []byte{value & 15, value >> 4} {
			if nibble == 15 {
				filler = true
				continue
			}
			if nibble > 9 || filler {
				return "", errors.New("invalid MSISDN BCD")
			}
			digits.WriteByte('0' + nibble)
		}
	}
	number := digits.String()
	if !ValidNumber(number) {
		return "", errors.New("invalid MSISDN digits")
	}
	switch b[1] & 0x70 {
	case 0x10:
		return "+" + number, nil
	case 0, 0x20:
		return number, nil
	default:
		return "", errors.New("unsupported MSISDN numbering type")
	}
}

func ValidNumber(number string) bool {
	number = strings.TrimPrefix(number, "+")
	if len(number) < 5 || len(number) > 15 {
		return false
	}
	nonzero := false
	for _, digit := range number {
		if digit < '0' || digit > '9' {
			return false
		}
		if digit != '0' {
			nonzero = true
		}
	}
	return nonzero
}

func parseRecordOutput(output string) ([]byte, error) {
	_, result, ok := strings.Cut(output, "Read result:")
	if !ok {
		return nil, errors.New("missing MSISDN read result")
	}
	result = strings.Join(strings.Fields(result), "")
	result = strings.ReplaceAll(result, ":", "")
	if len(result) > 510 {
		return nil, errors.New("oversized MSISDN record")
	}
	return hex.DecodeString(result)
}
