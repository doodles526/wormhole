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

	sessions map[string]map[messages.SessionType]session.Session
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

	msg, err := wConn.ReadMessage()
	if err != nil {
		d.logger.Errorf("Error reading message: %s", err.Error())
		return
	}

	handshake, ok := msg.(*messages.Handshake)
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

func (d *DispatchHandler) handleNewSession(h *messages.Handshake) error {
	return nil
}

func (d *DispatchHandler) handleNewTunnel(h *messages.Handshake) error {
	return nil
}

func (d *DispatchHandler) Close() {
}
