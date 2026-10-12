package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
	"golang.org/x/term"
)

func (a *app) shareCmd() *cobra.Command {
	var (
		qr  bool
		png string
	)
	cmd := &cobra.Command{
		Use:   "share <server>",
		Short: "Print a server's share link (or QR code)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var uri string
			err := a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				srv, err := resolveServer(ctx, c, args[0])
				if err != nil {
					return err
				}
				resp, err := c.Subscriptions.GetShareLink(ctx, &berylliumv1.GetShareLinkRequest{
					Target: &berylliumv1.GetShareLinkRequest_ServerId{ServerId: srv.GetId()}})
				uri = resp.GetUri()
				return err
			})
			if err != nil {
				return err
			}
			return a.emitSecret(cmd.ErrOrStderr(), uri, qr, png)
		},
	}
	cmd.Flags().BoolVar(&qr, "qr", false, "show a QR code instead of the link")
	cmd.Flags().StringVar(&png, "png", "", "write the QR code to a PNG file")
	return cmd
}

func (a *app) subQRCmd() *cobra.Command {
	var (
		png      string
		showLink bool
	)
	cmd := &cobra.Command{
		Use:   "qr <id|name>",
		Short: "Show a subscription as a QR code, e.g. to add it on a phone",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var uri string
			err := a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				sub, err := resolveSub(ctx, c, args[0])
				if err != nil {
					return err
				}
				resp, err := c.Subscriptions.GetShareLink(ctx, &berylliumv1.GetShareLinkRequest{
					Target: &berylliumv1.GetShareLinkRequest_SubscriptionId{SubscriptionId: sub.GetId()}})
				uri = resp.GetUri()
				return err
			})
			if err != nil {
				return err
			}
			return a.emitSecret(cmd.ErrOrStderr(), uri, !showLink, png)
		},
	}
	cmd.Flags().StringVar(&png, "png", "", "write the QR code to a PNG file instead")
	cmd.Flags().BoolVar(&showLink, "link", false, "print the URL instead of a QR code")
	return cmd
}

func (a *app) emitSecret(errOut io.Writer, uri string, qr bool, png string) error {
	secretWarning(errOut)
	switch {
	case png != "":
		data, err := qrcode.Encode(uri, qrcode.Medium, 768)
		if err != nil {
			return err
		}
		if err := os.WriteFile(png, data, 0o600); err != nil {
			return err
		}
		fmt.Fprintln(a.out, "QR code written to", png)
		return nil
	case qr:
		return printQR(a.out, uri)
	case a.json:
		return a.printJSON(map[string]string{"uri": uri})
	default:
		fmt.Fprintln(a.out, uri)
		return nil
	}
}

// printQR renders a QR code with half blocks, two modules per character
// row, in black on white so it scans on dark and light terminals alike.
func printQR(w io.Writer, content string) error {
	code, err := qrcode.New(content, qrcode.Low)
	if err != nil {
		return err
	}
	bm := code.Bitmap() // includes the quiet zone
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		if cols, _, err := term.GetSize(int(f.Fd())); err == nil && len(bm[0]) > cols {
			return errors.New("the terminal is too narrow for this QR code; widen it or use --png <file>")
		}
	}
	const on, off = "\x1b[30;47m", "\x1b[0m"
	var b strings.Builder
	for y := 0; y < len(bm); y += 2 {
		b.WriteString(on)
		for x := range bm[y] {
			top := bm[y][x]
			bottom := y+1 < len(bm) && bm[y+1][x]
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString(off + "\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}
