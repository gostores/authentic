// File contains Compare functionality
//
// https://tools.ietf.org/html/rfc4511
//
// CompareRequest ::= [APPLICATION 14] SEQUENCE {
//              entry           LDAPDN,
//              ava             AttributeValueAssertion }
//
// AttributeValueAssertion ::= SEQUENCE {
//              attributeDesc   AttributeDescription,
//              assertionValue  AssertionValue }
//
// AttributeDescription ::= LDAPString
//                         -- Constrained to <attributedescription>
//                         -- [RFC4512]
//
// AttributeValue ::= OCTET STRING
//

package ldap

import (
	"errors"
	"fmt"

	"github.com/gostores/sincere/asno"
)

// Compare checks to see if the attribute of the dn matches value. Returns true if it does otherwise
// false with any error that occurs if any.
func (l *Conn) Compare(dn, attribute, value string) (bool, error) {
	packet := asno.Encode(asno.ClassUniversal, asno.TypeConstructed, asno.TagSequence, nil, "LDAP Request")
	packet.AppendChild(asno.NewInteger(asno.ClassUniversal, asno.TypePrimitive, asno.TagInteger, l.nextMessageID(), "MessageID"))

	request := asno.Encode(asno.ClassApplication, asno.TypeConstructed, ApplicationCompareRequest, nil, "Compare Request")
	request.AppendChild(asno.NewString(asno.ClassUniversal, asno.TypePrimitive, asno.TagOctetString, dn, "DN"))

	ava := asno.Encode(asno.ClassUniversal, asno.TypeConstructed, asno.TagSequence, nil, "AttributeValueAssertion")
	ava.AppendChild(asno.NewString(asno.ClassUniversal, asno.TypePrimitive, asno.TagOctetString, attribute, "AttributeDesc"))
	ava.AppendChild(asno.Encode(asno.ClassUniversal, asno.TypeConstructed, asno.TagOctetString, value, "AssertionValue"))
	request.AppendChild(ava)
	packet.AppendChild(request)

	l.Debug.PrintPacket(packet)

	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return false, err
	}
	defer l.finishMessage(msgCtx)

	l.Debug.Printf("%d: waiting for response", msgCtx.id)
	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return false, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}
	packet, err = packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return false, err
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return false, err
		}
		asno.PrintPacket(packet)
	}

	if packet.Children[1].Tag == ApplicationCompareResponse {
		resultCode, resultDescription := getLDAPResultCode(packet)
		if resultCode == LDAPResultCompareTrue {
			return true, nil
		} else if resultCode == LDAPResultCompareFalse {
			return false, nil
		} else {
			return false, NewError(resultCode, errors.New(resultDescription))
		}
	}
	return false, fmt.Errorf("Unexpected Response: %d", packet.Children[1].Tag)
}
