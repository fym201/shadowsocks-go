package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"

	"github.com/fym201/go-logger/logger"
	ss "github.com/fym201/shadowsocks-go/shadowsocks"
)

const logCntDelta = 100
const dnsGoroutineNum = 64

type PortListener struct {
	password string
	listener net.Listener
}

type Server struct {
	logger         *logger.Logger
	Config         *ss.Config
	ConnectCount   int
	nextLogConnCnt int
	Running        bool

	listeners     map[string]*PortListener
	listener_lock *sync.Mutex
}

//创建一个服务
func NewServer(config *ss.Config, out *logger.Logger) (sev *Server, err error) {
	if err = checkConfig(config); err != nil {
		return
	}

	sev = &Server{logger: out,
		Config:        config,
		listeners:     map[string]*PortListener{},
		listener_lock: &sync.Mutex{}}
	sev.nextLogConnCnt = logCntDelta
	return
}

func checkConfig(config *ss.Config) (err error) {
	if config == nil {
		err = errors.New("config is nil")
		return
	}

	if len(config.PortPassword) == 0 {

		if config.ServerPort == 0 {
			err = errors.New("no ServerPort found")
			return
		}

		if config.Password == "" {
			err = errors.New("ServerPassword is empty")
			return
		}
		config.PortPassword = map[string]string{strconv.Itoa(config.ServerPort): config.Password}
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			fmt.Println("given port_password, ignore server_port and password option")
		}
	}

	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}

	if err = ss.CheckCipherMethod(config.Method); err != nil {
		return
	}
	return
}

//启动服务
func (s *Server) Start() error {
	if s.Running {
		return nil
	}
	s.Running = true
	for port, password := range s.Config.PortPassword {
		go s.run(port, password)
	}
	return nil
}

//停止服务
func (s *Server) Stop() error {
	if !s.Running {
		return nil
	}
	s.Running = false
	s.listener_lock.Lock()
	var tm_ports []string
	for port, listenner := range s.listeners {
		listenner.listener.Close()
		tm_ports = append(tm_ports, port)
	}
	for _, port := range tm_ports {
		delete(s.listeners, port)
	}
	s.listener_lock.Unlock()
	return nil
}

//run a server on given port
func (s *Server) run(port, password string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		s.logger.Fatalf("error listening port %v: %v\n", port, err)
		return
	}
	s.add(port, password, ln)
	var cipher *ss.Cipher
	s.logger.Infof("server listening port %v ...\n", port)
	for s.Running {
		conn, err := ln.Accept()
		if err != nil {
			// listener maybe closed to update password
			s.logger.Errorf("accept error: %v\n", err)
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			s.logger.Debug("creating cipher for port:", port)
			cipher, err = ss.NewCipher(s.Config.Method, password)
			if err != nil {
				s.logger.Errorf("Error generating cipher for port: %s %v\n", port, err)
				conn.Close()
				continue
			}
		}
		go s.handleConnection(ss.NewConn(conn, cipher.Copy()))
	}
}

func (s *Server) add(port, password string, listener net.Listener) {
	s.listener_lock.Lock()
	s.listeners[port] = &PortListener{password, listener}
	s.listener_lock.Unlock()
}

func (s *Server) get(port string) (pl *PortListener, ok bool) {
	s.listener_lock.Lock()
	pl, ok = s.listeners[port]
	s.listener_lock.Unlock()
	return
}

func (s *Server) del(port string) {
	pl, ok := s.get(port)
	if !ok {
		return
	}
	pl.listener.Close()
	s.listener_lock.Lock()
	delete(s.listeners, port)
	s.listener_lock.Unlock()
}

// Update port password would first close a port and restart listening on that port
func (s *Server) UpdatePortPasswd(port, password string) {
	pl, ok := s.get(port)
	if !ok {
		s.logger.Info("new port %s added\n", port)
	} else {
		if pl.password == password {
			return
		}
		s.logger.Infof("closing port %s to update password\n", port)
		pl.listener.Close()
	}

	go s.run(port, password)
}

//update server config
func (s *Server) UpdateConfig(config *ss.Config) {
	if err := checkConfig(config); err != nil {
		s.logger.Error("UpdateConfig error:", err.Error())
	}

	s.Config = config

	s.listener_lock.Lock()
	var tm_ports []string
	for port, conn := range s.listeners {
		if pw, ok := config.PortPassword[port]; ok {
			s.UpdatePortPasswd(port, pw)
		} else {
			tm_ports = append(tm_ports, port)
			conn.listener.Close()
		}
	}
	for _, port := range tm_ports {
		delete(s.listeners, port)
	}
	s.listener_lock.Unlock()
	s.logger.Info("password updated")
}

func (s *Server) getRequest(conn *ss.Conn) (host string, extra []byte, err error) {
	const (
		idType  = 0 // address type index
		idIP0   = 1 // ip addres start index
		idDmLen = 1 // domain address length index
		idDm0   = 2 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
		lenIPv6   = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
		lenDmBase = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
	)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, 260)
	var n int
	// read till we get possible domain length field
	ss.SetReadTimeout(conn)
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", buf[idType])
		return
	}

	if n < reqLen { // rare case
		ss.SetReadTimeout(conn)
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else if n > reqLen {
		// it's possible to read more than just the request head
		extra = buf[reqLen:n]
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

//handle connection
func (s *Server) handleConnection(conn *ss.Conn) {
	var host string

	s.ConnectCount++ // this maybe not accurate, but should be enough
	if s.ConnectCount-s.nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		s.logger.Info("Number of client connections reaches ", s.nextLogConnCnt)
		s.nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	s.logger.Infof("new client %s->%s\n", conn.RemoteAddr().String(), conn.LocalAddr())
	closed := false
	defer func() {
		s.logger.Infof("closed pipe %s<->%s\n", conn.RemoteAddr(), host)
		s.ConnectCount--
		if !closed {
			conn.Close()
		}
	}()

	host, extra, err := s.getRequest(conn)
	if err != nil {
		s.logger.Errorf("error getting request", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	s.logger.Info("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			s.logger.Error("dial error:", err)
		} else {
			s.logger.Error("error connecting to:", host, err)
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	// write extra bytes read from
	if extra != nil {
		s.logger.Debug("getRequest read extra data, writing to remote, len", len(extra))
		if _, err = remote.Write(extra); err != nil {
			s.logger.Error("write request extra error:", err)
			return
		}
	}
	s.logger.Error("piping %s<->%s", conn.RemoteAddr(), host)
	go ss.PipeThenClose(conn, remote, ss.SET_TIMEOUT)
	ss.PipeThenClose(remote, conn, ss.NO_TIMEOUT)
	closed = true
	return
}
