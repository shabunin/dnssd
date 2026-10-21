//go:build !linux

package dnssd

import (
	"context"

	"github.com/shabunin/dnssd/log"
)

func (r *responder) linkSubscribe(context.Context) {
	log.Info.Println("dnssd: unable to wait for link updates")
}
