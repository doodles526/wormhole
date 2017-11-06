package messages

import (
	"encoding/json"
	"fmt"
	"reflect"
)

//messages sent directly over the wire

// TypeMap stores a list of messages types and provides a way to deserialize messages
var TypeMap map[string]reflect.Type

func init() {
	TypeMap = make(map[string]reflect.Type)

	t := func(obj interface{}) reflect.Type { return reflect.TypeOf(obj).Elem() }
	TypeMap["AuthControl"] = t((*AuthControl)(nil))
	TypeMap["ControlSuccess"] = t((*ControlSuccess)(nil))
	TypeMap["AuthTunnel"] = t((*AuthTunnel)(nil))
	TypeMap["TunnelSuccess"] = t((*TunnelSuccess)(nil))
	TypeMap["AuthFailed"] = t((*AuthFailed)(nil))
	TypeMap["RequestAuth"] = t((*RequestAuth)(nil))
	TypeMap["OpenTunnel"] = t((*OpenTunnel)(nil))
	TypeMap["Ping"] = t((*Ping)(nil))
	TypeMap["Pong"] = t((*Pong)(nil))
	TypeMap["Shutdown"] = t((*Shutdown)(nil))
	TypeMap["HelloRequest"] = t((*HelloRequest)(nil))
	TypeMap["HelloResponse"] = t((*HelloResponse)(nil))
	TypeMap["ConnectionInfo"] = t((*ConnectionInfo)(nil))
	TypeMap["ConnectionUnsupported"] = t((*ConnectionUnsupported)(nil))
	TypeMap["Capabilities"] = t((*Capabilities)(nil))
}

// Message is a generic interface for all the messages
type Message interface{}

// Envelope is a wrapper struct used to encode message types as they are serialized to JSON
type Envelope struct {
	Type    string
	Payload json.RawMessage
}

type HelloRequest struct {
	StartTLS bool
}

type HelloResponse struct {
	OK           bool
	Error        string
	Capabilities *Capabilities
}

type Capabilities struct {
	SessionTypes []SessionType
	Insecure     bool
	Secure       bool
}

func (cap *Capabilities) Supports(ci *ConnectionInfo) (bool, string) {
	if !(ci.Insecure && cap.Insecure) {
		return false, fmt.Sprintf("Insecure connection is not supported")
	}

	if !(!ci.Insecure && cap.Secure) {
		return false, fmt.Sprintf("Secure connection is not supported")
	}

	for _, sType := range cap.SessionTypes {
		if sType == ci.SessionType {
			return true, ""
		}
	}

	var typeName string

	switch ci.SessionType {
	case SSH:
		typeName = "ssh"
	case HTTP2:
		typeName = "http2"
	case TCP:
		typeName = "tcp"
	}

	return false, fmt.Sprintf("SessionType %s is not supported", typeName)
}

func (c1 *Capabilities) MutualCapabilities(c2 *Capabilities) Capabilities {
	c := &Capabilities{
		SessionTypes: []SessionType{},
	}
	for _, s1Type := range c1.SessionTypes {
		for _, s2Type := range c2.SessionTypes {
			if s1Type == s2Type {
				c.SessionTypes = append(c.SessionTypes, s1Type)
			}
		}
	}

	c.Insecure = c1.Insecure && c2.Insecure
	c.Secure = c1.Secure && c1.Secure

	return c
}

type ConnectionType int

const (
	Control ConnectionType = iota
	Tunnel
)

type SessionType int

const (
	SSH SessionType = iota
	HTTP2
	TCP
)

type ConnectionInfo struct {
	SessionType    SessionType
	ConnectionType ConnectionType
	Insecure       bool
}

type ConnectionUnsupported struct {
	Error string
}

type AuthFailed struct {
	Error string
}

// AuthControl is sent by the client to create and authenticate a new session
type AuthControl struct {
	Token string
}

type RequestAuth struct {
}

type ControlSuccess struct {
}

type TunnelSuccess struct{}

// AuthTunnel is sent by the client to create and authenticate a tunnel connection
type AuthTunnel struct {
	ClientID string
	Token    string
}

// OpenTunnel is sent by server to the client to request a new Tunnel connection
type OpenTunnel struct {
	ClientID string
}

// Shutdown is sent either by server or client to indicate that the session
// should be torn down
type Shutdown struct {
	Error string
}

// Ping is sent to request a Pong response and check the liveness of the connection
type Ping struct{}

// Pong is a response ot the Ping message
type Pong struct{}

func unpack(buffer []byte, msgIn Message) (msg Message, err error) {
	var env Envelope
	if err = json.Unmarshal(buffer, &env); err != nil {
		return
	}

	if msgIn == nil {
		t, ok := TypeMap[env.Type]

		if !ok {
			err = fmt.Errorf("Unsupported message type %s", env.Type)
			return
		}

		// guess type
		msg = reflect.New(t).Interface().(Message)
	} else {
		msg = msgIn
	}

	err = json.Unmarshal(env.Payload, &msg)
	return
}

// Unpack deserializes byte array into a message
func Unpack(buffer []byte) (msg Message, err error) {
	return unpack(buffer, nil)
}

// Pack serializes a message into a byte array
func Pack(payload interface{}) ([]byte, error) {
	return json.Marshal(struct {
		Type    string
		Payload interface{}
	}{
		Type:    reflect.TypeOf(payload).Elem().Name(),
		Payload: payload,
	})
}
