package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skip2/go-qrcode"
)

// The half-block rendering must decode back to exactly the QR bitmap.
func TestPrintQRMatchesBitmap(t *testing.T) {
	const content = "https://sub.example.com:2096/sub/abcdef123456"
	var buf bytes.Buffer
	if err := printQR(&buf, content); err != nil {
		t.Fatal(err)
	}
	code, _ := qrcode.New(content, qrcode.Low)
	want := code.Bitmap()

	text := strings.NewReplacer("\x1b[30;47m", "", "\x1b[0m", "").Replace(buf.String())
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) != (len(want)+1)/2 {
		t.Fatalf("rows = %d, want %d", len(lines), (len(want)+1)/2)
	}
	for row, line := range lines {
		cells := []rune(line)
		if len(cells) != len(want[0]) {
			t.Fatalf("row %d width = %d, want %d", row, len(cells), len(want[0]))
		}
		for x, c := range cells {
			top, bottom := c == '█' || c == '▀', c == '█' || c == '▄'
			y := row * 2
			if top != want[y][x] || (y+1 < len(want) && bottom != want[y+1][x]) {
				t.Fatalf("module mismatch at x=%d y=%d (%q)", x, y, c)
			}
		}
	}
}
