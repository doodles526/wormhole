package session

import (
	"net"

	"github.com/sirupsen/logrus"
	"github.com/superfly/wormhole/config"
	"github.com/superfly/wormhole/messages"
	wnet "github.com/superfly/wormhole/net"
)

// Session hold information about connected client
type Session interface {
	ID() string
	Agent() string
	BackendID() string
	NodeID() string
	Client() string
	ClientIP() string
	Cluster() string
	Endpoint() string
	Key() string
	Release() *messages.Release
	RequireStream() error
	// SetReady indicates that the session has been added
	// to the proper backends and is ready for accepting tunnels
	// For example, this could send a ControlSuccess message
	SetReady() error
	Close()
}

type UniTunneler interface {
	AddTunnel(*wnet.Conn) error
}

type SessionArgs struct {
	Logger     *logrus.Logger
	ClusterURL string
	NodeID     string
	Pool       *redis.Pool
	Conn       *wnet.Conn
	Config     *config.ServerConfig
	BackendID  string
}

type baseSession struct {
	id           string
	agent        string
	nodeID       string
	backendID    string
	clientAddr   string
	EndpointAddr string
	ClusterURL   string

	release *messages.Release
	store   *RedisStore
	logger  *logrus.Entry
}

func (s *baseSession) ID() string {
	return s.id
}

func (s *baseSession) Agent() string {
	return s.agent
}

func (s *baseSession) BackendID() string {
	return s.backendID
}

func (s *baseSession) NodeID() string {
	return s.nodeID
}

func (s *baseSession) Client() string {
	return s.clientAddr
}

func (s *baseSession) ClientIP() string {
	host, _, _ := net.SplitHostPort(s.clientAddr)
	return host
}

func (s *baseSession) Cluster() string {
	return s.ClusterURL
}

func (s *baseSession) Endpoint() string {
	return s.EndpointAddr
}

func (s *baseSession) Key() string {
	return "session:" + s.id
}

func (s *baseSession) Release() *messages.Release {
	return s.release
}
