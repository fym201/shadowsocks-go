package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"

	"github.com/fym201/loggo"
	ss "github.com/fym201/shadowsocks-go/shadowsocks"
)

const logCntDelta = 100
const dnsGoroutineNum = 64

type Server struct {
	logger         *loggo.Logger
	Config         *Config
	ConnectCount   int
	nextLogConnCnt int
	Running        bool
	listener       net.Listener
}

// Create a shawdowsocks server
func NewServer(config *Config, out *loggo.Logger) (sev *Server, err error) {
	if err = CheckConfig(config); err != nil {
		return
	}

	sev = &Server{logger: out, Config: config, nextLogConnCnt: logCntDelta}

	return
}

func NewAndStartServer(config *Config, out *loggo.Logger) (sev *Server, err error) {
	if sev, err = NewServer(config, out); err != nil {
		return
	}
	err = sev.Start()
	return
}

//启动服务
func (s *Server) Start() error {
	if s.Running {
		return nil
	}
	s.Running = true

	go s.run()
	return nil
}

//停止服务
func (s *Server) Stop() error {
	if !s.Running {
		return nil
	}
	s.Running = false
	s.listener.Close()
	return nil
}

//run a server on given port
func (s *Server) run() {
	ln, err := net.Listen("tcp", s.Config.Address())
	if err != nil {
		s.logger.Fatalf("error listening ip:%v port:%v [%v]", s.Config.Ip, s.Config.Port, err)
		return
	}
	s.listener = ln
	var cipher *ss.Cipher
	s.logger.Infof("server listening ip:%v port:%v ...", s.Config.Ip, s.Config.Port)
	for s.Running {
		conn, err := ln.Accept()
		if err != nil {
			// listener maybe closed to update password
			s.logger.Errorf("accept error: %v\n", err)
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			s.logger.Debug("creating cipher for port:", s.Config.Port)
			cipher, err = ss.NewCipher(s.Config.Method, s.Config.Password)
			if err != nil {
				s.logger.Errorf("Error generating cipher for port: %s %v\n", s.Config.Port, err)
				conn.Close()
				continue
			}
		}
		go s.handleConnection(ss.NewConn(conn, cipher.Copy()))
	}
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
	s.logger.Infof("new client %s->%s", conn.RemoteAddr().String(), conn.LocalAddr())
	closed := false
	defer func() {
		s.logger.Infof("closed pipe %s<->%s", conn.RemoteAddr(), host)
		s.ConnectCount--
		if !closed {
			conn.Close()
		}
	}()

	host, extra, err := s.getRequest(conn)
	if err != nil {
		s.logger.Error("error getting request", conn.RemoteAddr(), conn.LocalAddr(), err)
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
	s.logger.Infof("piping %s<->%s", conn.RemoteAddr(), host)
	go ss.PipeThenClose(conn, remote, ss.SET_TIMEOUT)
	ss.PipeThenClose(remote, conn, ss.NO_TIMEOUT)
	closed = true
	return
}
