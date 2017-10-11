package remote

import (
	"crypto/tls"
	"net"

	"github.com/garyburd/redigo/redis"
	"github.com/sirupsen/logrus"
	"github.com/superfly/wormhole/config"
	"github.com/superfly/wormhole/messages"
	wnet "github.com/superfly/wormhole/net"
	"github.com/superfly/wormhole/session"
)

type DispatchHandler struct {
	sConfig   *config.ServerConfig
	tlsConfig *tls.Config

	logger *logrus.Entry

	sessions map[string]session.Session
	sm       sync.RWMutex
	store    Store
}

func NewDispatchHandler(cfg *config.ServerConfig, pool *redis.Pool) {
}

func (d *DispatchHandler) Serve(conn *net.TCPConn) {
	wConn, err := wnet.NewServerConn(conn, d.tlsConfig)
	if err != nil {
		d.logger.Errorf("Could not create new server conn: %s", err.Error())
	}

	if err := wConn.NegotiateHello(); err != nil {
		d.logger.Errorf("Error negotiating Hello: %s", err.Error())
		return
	}

	hm, err := wConn.ReadMessage()
	if err != nil {
		d.logger.Errorf("Error reading message: %s", err.Error())
		return
	}

	handshake, ok := hm.(*messages.Handshake)
	if !ok {
		d.logger.Errorf("Unexpected message. Expected Handshake")
		return
	}

	switch handshake.ConnectionType {
	case messages.Control:
		if err := d.handleNewSession(handshake); err != nil {
			d.logger.Errorf("Error handling new session: %s", err.Error())
			return
		}
	case messages.Tunnel:
		if err := d.handleNewTunnel(handshake); err != nil {
			d.logger.Errorf("Error handling new tunnel: %s", err.Error())
			return
		}
	default:
		d.logger.Errorf("No known connection type in handshake")
	}
}

func (d *DispatchHandler) validateAuthControl(a *messages.AuthControl) (string, error) {
	bID, err := store.BackendIDFromToken(a.Token)
	if err != nil {
		return "", err
	}

	if bID == "" {
		return "", fmt.Errorf("No valid backend matching token")
	}

	return bID, nil
}

func (d *DispatchHandler) handleNewSession(c *wnet.Conn, h *messages.Handshake) error {
	msg, err := c.ReadMessage()
	if err != nil {
		return err
	}

	authMsg, ok := msg.(*messages.AuthControl)
	if !ok {
		return fmt.Errorf("Unexpected message. Expected AuthControl")
	}

	bID, err := d.validateAuthControl(authMsg)
	if err != nil {
		aFail := &messages.AuthFailed{
			Error: "Could not validate Token",
		}
		if err := c.WriteMessage(aFail); err != nil {
			return err
		}
		return err
	}

	// Connection has now been validated
	// And is trusted so long as the current TLS
	// negotiation is maintained

	sessArgs := &SessionArgs{
		Logger:     d.sConfig.Logger,
		BackendID:  bID,
		NodeID:     d.sConfig.NodeID,
		Pool:       d.pool,
		Conn:       c,
		ClusterURL: d.sConfig.ClusterURL,
		Config:     d.sConfig,
	}

	var sess Session
	switch h.SessionType {
	case messages.SSH:
		sess, err = NewSSHSession(sessArgs)
		if err != nil {
			return err
		}
	case messages.HTTP2:
		sess, err = NewHTTP2Session(sessArgs)
		if err != nil {
			return err
		}
	case messages.TCP:
		sess, err = NewTCPSession(sessArgs)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Unknown session type: %v", h.SessionType)
	}

	d.sm.Lock()
	d.sessions[sess.ID()] = sess
	d.sm.Unlock()

	if err := sess.SessionReady(); err != nil {
		return err
	}

	// TODO: Initiate stream now, or allow client to initiate?
	return nil
}

// validateAuthTunnel ensures the auth is proper. It also returns a safe to report error
// So you don't have to scrub the error for returning to the client
func (d *DispatchHandler) validateAuthTunnel(m *messages.AuthTunnel) (Session, error) {
	bID, err := store.BackendIDFromToken(m.Token)
	if err != nil {
		d.logger.Errorf("Error retrieving backend ID: %s", err.Error())
		return nil, fmt.Errorf("Error verifying backend")
	}

	if bID == "" {
		return nil, fmt.Errorf("No valid backend matching token")
	}

	sm.RLock()
	sess, ok := d.sessions[m.ClientID]
	sm.RUnlock()
	if !ok {
		return nil, fmt.Errorf("No session for ClientID")
	}

	return sess, nil
}

func (d *DispatchHandler) handleNewTunnel(c *wnet.Conn, h *messages.Handshake) error {
	msg, err := c.ReadMessage()
	if err != nil {
		return err
	}

	authMsg, ok := msg.(*messages.AuthTunnel)
	if !ok {
		return fmt.Errorf("Unexpected message. Expected AuthControl")
	}

	sess, err := validateAuthTunnel(authMsg)
	if err != nil {
		aFail := &messages.AuthFailed{
			Error: err.Error(),
		}
		if err := c.WriteMessage(aFail); err != nil {
			return err
		}
		return err
	}

	if err := sess.AddTunnel(c); err != nil {
		return err
	}

	return nil
}

func (d *DispatchHandler) Close() {
}
