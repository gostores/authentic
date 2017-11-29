package ldap

import (
	"log"

	"github.com/gostores/encoding/asn1"
)

// debugging type
//     - has a Printf method to write the debug output
type debugging bool

// write debug output
func (debug debugging) Printf(format string, args ...interface{}) {
	if debug {
		log.Printf(format, args...)
	}
}

func (debug debugging) PrintPacket(packet *asn1.Packet) {
	if debug {
		asn1.PrintPacket(packet)
	}
}
