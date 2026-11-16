package main

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestScriptScannerReportsAnOversizedLine(t *testing.T) {
	sc := scriptScanner(strings.NewReader(strings.Repeat("a", scriptLimit+1) + "\n"))
	if sc.Scan() {
		t.Fatal("scanned an oversized line")
	}
	if !errors.Is(sc.Err(), bufio.ErrTooLong) {
		t.Fatalf("oversized line error = %v, want %v", sc.Err(), bufio.ErrTooLong)
	}
}

func TestScriptScannerReadsALineAtTheLimit(t *testing.T) {
	line := strings.Repeat("a", scriptLimit)
	sc := scriptScanner(strings.NewReader(line + "\n"))
	if !sc.Scan() {
		t.Fatalf("a line at the limit failed: %v", sc.Err())
	}
	if sc.Text() != line {
		t.Fatal("the line changed")
	}
}
