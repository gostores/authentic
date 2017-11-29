//
// https://tools.ietf.org/html/rfc4511
//
// DelRequest ::= [APPLICATION 10] LDAPDN

package ldap

import (
	"errors"
	"log"

	"github.com/gostores/encoding/asn1"
)

// DelRequest implements an LDAP deletion request
type DelRequest struct {
	// DN is the name of the directory entry to delete
	DN string
	// Controls hold optional controls to send with the request
	Controls []Control
}

func (d DelRequest) encode() *asn1.Packet {
	request := asn1.Encode(asn1.ClassApplication, asn1.TypePrimitive, ApplicationDelRequest, d.DN, "Del Request")
	request.Data.Write([]byte(d.DN))
	return request
}

// NewDelRequest creates a delete request for the given DN and controls
func NewDelRequest(DN string,
	Controls []Control) *DelRequest {
	return &DelRequest{
		DN:       DN,
		Controls: Controls,
	}
}

// Del executes the given delete request
func (l *Conn) Del(delRequest *DelRequest) error {
	packet := asn1.Encode(asn1.ClassUniversal, asn1.TypeConstructed, asn1.TagSequence, nil, "LDAP Request")
	packet.AppendChild(asn1.NewInteger(asn1.ClassUniversal, asn1.TypePrimitive, asn1.TagInteger, l.nextMessageID(), "MessageID"))
	packet.AppendChild(delRequest.encode())
	if delRequest.Controls != nil {
		packet.AppendChild(encodeControls(delRequest.Controls))
	}

	l.Debug.PrintPacket(packet)

	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return err
	}
	defer l.finishMessage(msgCtx)

	l.Debug.Printf("%d: waiting for response", msgCtx.id)
	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}
	packet, err = packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return err
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return err
		}
		asn1.PrintPacket(packet)
	}

	if packet.Children[1].Tag == ApplicationDelResponse {
		resultCode, resultDescription := getLDAPResultCode(packet)
		if resultCode != 0 {
			return NewError(resultCode, errors.New(resultDescription))
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}

	l.Debug.Printf("%d: returning", msgCtx.id)
	return nil
}
