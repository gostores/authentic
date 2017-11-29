//
// https://tools.ietf.org/html/rfc4511
//
// AddRequest ::= [APPLICATION 8] SEQUENCE {
//      entry           LDAPDN,
//      attributes      AttributeList }
//
// AttributeList ::= SEQUENCE OF attribute Attribute

package ldap

import (
	"errors"
	"log"

	"github.com/gostores/authentic/asno"
)

// Attribute represents an LDAP attribute
type Attribute struct {
	// Type is the name of the LDAP attribute
	Type string
	// Vals are the LDAP attribute values
	Vals []string
}

func (a *Attribute) encode() *asno.Packet {
	seq := asno.Encode(asno.ClassUniversal, asno.TypeConstructed, asno.TagSequence, nil, "Attribute")
	seq.AppendChild(asno.NewString(asno.ClassUniversal, asno.TypePrimitive, asno.TagOctetString, a.Type, "Type"))
	set := asno.Encode(asno.ClassUniversal, asno.TypeConstructed, asno.TagSet, nil, "AttributeValue")
	for _, value := range a.Vals {
		set.AppendChild(asno.NewString(asno.ClassUniversal, asno.TypePrimitive, asno.TagOctetString, value, "Vals"))
	}
	seq.AppendChild(set)
	return seq
}

// AddRequest represents an LDAP AddRequest operation
type AddRequest struct {
	// DN identifies the entry being added
	DN string
	// Attributes list the attributes of the new entry
	Attributes []Attribute
}

func (a AddRequest) encode() *asno.Packet {
	request := asno.Encode(asno.ClassApplication, asno.TypeConstructed, ApplicationAddRequest, nil, "Add Request")
	request.AppendChild(asno.NewString(asno.ClassUniversal, asno.TypePrimitive, asno.TagOctetString, a.DN, "DN"))
	attributes := asno.Encode(asno.ClassUniversal, asno.TypeConstructed, asno.TagSequence, nil, "Attributes")
	for _, attribute := range a.Attributes {
		attributes.AppendChild(attribute.encode())
	}
	request.AppendChild(attributes)
	return request
}

// Attribute adds an attribute with the given type and values
func (a *AddRequest) Attribute(attrType string, attrVals []string) {
	a.Attributes = append(a.Attributes, Attribute{Type: attrType, Vals: attrVals})
}

// NewAddRequest returns an AddRequest for the given DN, with no attributes
func NewAddRequest(dn string) *AddRequest {
	return &AddRequest{
		DN: dn,
	}

}

// Add performs the given AddRequest
func (l *Conn) Add(addRequest *AddRequest) error {
	packet := asno.Encode(asno.ClassUniversal, asno.TypeConstructed, asno.TagSequence, nil, "LDAP Request")
	packet.AppendChild(asno.NewInteger(asno.ClassUniversal, asno.TypePrimitive, asno.TagInteger, l.nextMessageID(), "MessageID"))
	packet.AppendChild(addRequest.encode())

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
		asno.PrintPacket(packet)
	}

	if packet.Children[1].Tag == ApplicationAddResponse {
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
