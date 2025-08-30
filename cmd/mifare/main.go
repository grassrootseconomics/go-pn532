package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	pn532 "github.com/ZaparooProject/go-pn532"
	"github.com/ZaparooProject/go-pn532/detection"
	_ "github.com/ZaparooProject/go-pn532/detection/i2c"
	_ "github.com/ZaparooProject/go-pn532/detection/spi"
	_ "github.com/ZaparooProject/go-pn532/detection/uart"
	"github.com/ZaparooProject/go-pn532/polling"
	"github.com/ZaparooProject/go-pn532/transport/uart"
)

const writeText = "https://sarafu.com"

func main() {
	os.Exit(run())
}

func run() int {
	level := slog.LevelInfo
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	device, err := connectToDevice()
	if err != nil {
		slog.Error("failed to connect to PN532", "err", err)
		return 1
	}
	defer device.Close()
	slog.Info("writer started")

	if err := runWriteOnce(device, writeText); err != nil {
		slog.Error("write failed", "err", err)
		return 1
	}

	slog.Info("writer exiting")
	return 0
}

func newTransportFromDevice(device detection.DeviceInfo) (pn532.Transport, error) {
	transport, err := uart.New(device.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to create UART transport: %w", err)
	}
	return transport, nil
}

func connectToDevice() (*pn532.Device, error) {
	var connectOpts []pn532.ConnectOption
	connectOpts = append(connectOpts,
		pn532.WithAutoDetection(),
		pn532.WithTransportFromDeviceFactory(newTransportFromDevice),
	)
	connectOpts = append(connectOpts, pn532.WithConnectTimeout(5*time.Second))

	device, err := pn532.ConnectDevice("", connectOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PN532 device: %w", err)
	}
	return device, nil
}

func runWriteOnce(device *pn532.Device, text string) error {
	sessionConfig := polling.DefaultConfig()
	session := polling.NewSession(device, sessionConfig)
	defer session.Close()

	slog.Info("waiting for tag to write", "text", text)

	timeout := 30 * time.Second
	err := session.WriteToNextTag(context.Background(), context.Background(), timeout, func(ctx context.Context, tag pn532.Tag) error {
		start := time.Now()
		slog.Info("tag detected", "type", tag.Type())
		slog.Info("tag detection took", "duration", time.Since(start))

		start = time.Now()
		xTag := tag.(*pn532.MIFARETag)
		slog.Info("type assertion took", "duration", time.Since(start))

		start = time.Now()
		message := &pn532.NDEFMessage{
			Records: []pn532.NDEFRecord{{Type: pn532.NDEFTypeURI, URI: text}},
		}
		slog.Info("NDEF message creation took", "duration", time.Since(start))

		if !xTag.IsNDEFFormatted() {
			start = time.Now()
			if err := xTag.FormatForNDEF(); err != nil {
				return err
			}
			slog.Info("NDEF formatting took", "duration", time.Since(start))

		}

		start = time.Now()
		if err := xTag.WriteNDEFAlternative(message); err != nil {
			return err
		}
		slog.Info("writing NDEF message took", "duration", time.Since(start))

		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
