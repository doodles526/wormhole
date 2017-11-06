package net

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/superfly/wormhole/messages"
)

type helloNegotiateFunc func(*Conn, *messages.Capabilities) (*messages.Capabilities, error)

type Conn struct {
	conn *net.TCPConn

	// tlsConn will always be a TLS wrapped version of conn
	// This is retained in case we ever want to downgrade a connection
	tlsConn   *tls.Conn
	tlsConfig *tls.Config
	tlsType   TLSWrapperFunc

	helloNegotiateFunc helloNegotiateFunc

	// b is a buffer to be employed when
	// closing a TLS connection such that if more data comes
	// through waiting for close-notify that it is retained
	b  []byte
	bm sync.Mutex

	// tlsM to ensure we don't race between upgrade/downgrade tls
	tlsM sync.RWMutex
}

func NewServerConn(conn *net.TCPConn, tlsConfig *tls.Config) (*Conn, error) {
	return &Conn{
		conn:               conn,
		tlsConfig:          tlsConfig,
		tlsType:            tls.Server,
		helloNegotiateFunc: negotiateServerHello,
		b:                  make([]byte, 0, 1024),
	}, nil
}

func NewClientConn(conn *net.TCPConn, tlsConfig *tls.Config) (*Conn, error) {
	return &Conn{
		conn:               conn,
		tlsConfig:          tlsConfig,
		tlsType:            tls.Client,
		helloNegotiateFunc: negotiateClientHello,
		b:                  make([]byte, 0, 1024),
	}, nil
}

func (c *Conn) NegotiateHello(cap *messages.Capabilities) (*messages.Capabilities, error) {
	return c.helloNegotiateFunc(c, cap)
}

func (c *Conn) Read(b []byte) (int, error) {
	c.bm.Lock()
	defer c.bm.Unlock()

	// read-out any buffer from close-notify
	if len(b) > 0 {
		n := copy(b, c.b)
		c.b = c.b[n:]
		return n, nil
	}

	c.tlsM.RLock()
	defer c.tlsM.RUnlock()

	if c.TLSEnabled() {
		return c.tlsConn.Read(b)
	}

	return c.conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	c.tlsM.RLock()
	defer c.tlsM.RUnlock()

	if c.TLSEnabled() {
		return c.tlsConn.Write(b)
	}
	return c.conn.Write(b)
}

func (c *Conn) ReadMessage() (messages.Message, error) {
	buf := make([]byte, 1024)
	nr, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return messages.Unpack(buf[:nr])
}

func (c *Conn) WriteMessage(msg messages.Message) error {
	msgData, err := messages.Pack(msg)
	if err != nil {
		return err
	}

	_, err = c.Write(msgData)
	if err != nil {
		return err
	}

	return nil
}

// UpgradeTLS upgrades this connection to TLS
// TODO: How to handle different tls configs?
func (c *Conn) UpgradeTLS() error {
	// control conn should never have a need for special
	// tls wrapping outside of modifications to tls.Config
	tc, err := GenericTLSWrap(c.conn, c.tlsConfig, c.tlsType)
	if err != nil {
		return err
	}

	c.tlsM.Lock()
	c.tlsConn = tc
	c.tlsM.Unlock()

	return nil
}

// DowngradeTLS forces this conn to stop using TLS
// Until TLS has been disabled, all Read/Write ops
// wil lock
func (c *Conn) DowngradeTLS() error {
	c.tlsM.Lock()
	defer c.tlsM.Unlock()

	if err := c.tlsConn.CloseWrite(); err != nil {
		return err
	}

	var err error
	var nr int
	for err != nil {
		buf := make([]byte, 1024)
		// TODO: Set deadline before reading out close-notify
		nr, err = c.tlsConn.Read(buf)
		if nr != 0 {
			c.b = append(c.b, buf...)
		}
	}
	if err != io.EOF {
		return err
	}

	return nil
}

func (c *Conn) Close() error {
	c.tlsM.RLock()
	defer c.tlsM.RUnlock()

	if c.TLSEnabled() {
		return c.tlsConn.Close()
	}

	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) TCPConn() *net.TCPConn {
	return c.conn
}

func (c *Conn) TLSConn() *tls.Conn {
	return c.tlsConn
}

func (c *Conn) TLSAvailable() bool {
	return c.tlsConfig != nil
}

func (c *Conn) TLSEnabled() bool {
	c.tlsM.RLock()
	defer c.tlsM.RUnlock()
	return c.tlsConn == nil
}

func negotiateServerHello(c *Conn, cap *messages.Capabilities) error {
	msg, err := c.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("Could not read message: %s", err.Error())
	}

	helloMsg, ok := msg.(*messages.HelloRequest)
	if !ok {
		return nil, fmt.Errorf("Unexpected message. Expected HelloRequest")
	}

	if helloMsg.StartTLS {
		if c.TLSAvailable() {
			helloResp := &messages.HelloResponse{
				OK:           true,
				Capabilities: cap,
			}
			if err := c.WriteMessage(helloResp); err != nil {
				return nil, fmt.Errorf("Could not send hello response: %s", err.Error())
			}
			if err := c.UpgradeTLS(); err != nil {
				return nil, fmt.Errorf("Could not upgrade connection to TLS: %s", err.Error())
			}
		} else {
			helloResp := &messages.HelloResponse{
				OK:    false,
				Error: "TLS not supported",
			}
			if err := c.WriteMessage(helloResp); err != nil {
				return nil, fmt.Errorf("Could not send hello response: %s", err.Error())
			}
			return nil, fmt.Errorf("Connection attempted TLS upgrade when server does not support TLS")
		}
	} else {
		if !c.TLSAvailable() {
			helloResp := &messages.HelloResponse{
				OK:           true,
				Capabilities: cap,
			}
			if err := c.WriteMessage(helloResp); err != nil {
				return nil, fmt.Errorf("Could not send hello response: %s", err.Error())
			}
		} else {
			helloResp := &messages.HelloResponse{
				OK:    false,
				Error: "Connections without TLS are unsupported",
			}
			if err := c.WriteMessage(helloResp); err != nil {
				return nil, fmt.Errorf("Could not send hello response: %s", err.Error())
			}
			return nil, fmt.Errorf("Connection did not request TLS upgrade when it is required")
		}
	}

	msg, err := c.ReadMessage()
	if err != nil {
		return fmt.Errorf("Could not read message: %s", err.Error())
	}

	cap, ok := msg.(*messages.Capabilities)
	if !ok {
		return fmt.Errorf("Unexpected message. Expected Capabilities")
	}

	return cap, nil
}

func negotiateClientHello(c *Conn, cap *messages.Capabilities) (*messages.Capabilities, error) {
	hReq := &messages.HelloRequest{
		StartTLS: c.TLSAvailable(),
	}

	if err := c.WriteMessage(hReq); err != nil {
		return nil, err
	}

	msg, err := c.ReadMessage()
	if err != nil {
		return nil, err
	}

	helloResp, ok := msg.(*messages.HelloResponse)
	if !ok {
		return nil, fmt.Errorf("Unexpted message type. Expected HelloResponse")
	}

	if helloResp.OK {
		if c.TLSAvailable() {
			if err := c.UpgradeTLS(); err != nil {
				return nil, fmt.Errorf("Could not upgrade connection to TLS: %s", err.Error())
			}
		}
	} else {
		return nil, fmt.Errorf("Error reported from server: %s", helloResp.Error)
	}

	if err := c.WriteMessage(cap); err != nil {
		return nil, fmt.Errorf("Error writing capabilities: %s", err.Error())
	}

	return helloResp.Capabilities, nil
}
