package main

import (
	"errors"
	"flag"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"github.com/fym201/shadowsocks-go/server"
	ss "github.com/fym201/shadowsocks-go/shadowsocks"

	"fmt"

	"github.com/fym201/loggo"
)

var (
	configFile string
	config     *ss.Config
	lg         *loggo.Logger
	servers    map[string]*server.Server
	servlock   *sync.Mutex
	serverIp   string
)

func updateConfig() {
	lg.Info("updating password")
	newconfig, err := ss.ParseConfig(configFile)
	if err != nil {
		lg.Errorf("error parsing config file %s to update password: %v", configFile, err)
		return
	}
	if err := unifyPortPassword(newconfig); err != nil {
		return
	}
	oldconfig := config
	config = newconfig
	for port, password := range newconfig.PortPassword {
		updatePortPassword(port, password)
		delete(oldconfig.PortPassword, port)
	}

	for port, _ := range oldconfig.PortPassword {
		del(port)
	}
	lg.Info("password updated")
}

func add(serv *server.Server) {
	servlock.Lock()
	servers[serv.Config.Port] = serv
	servlock.Unlock()
}

func del(port string) {
	if serv := get(port); serv != nil {
		serv.Stop()
	}
	servlock.Lock()
	delete(servers, port)
	servlock.Unlock()
}

func get(port string) *server.Server {
	servlock.Lock()
	defer servlock.Unlock()
	return servers[port]
}

func updatePortPassword(port, password string) {
	serv := get(port)
	if serv == nil {
		return
	}
	if serv.Config.Password == password {
		return
	}
	del(port)

	conf := &server.Config{Ip: serverIp, Port: port, Password: password, Method: config.Method}
	if serv, err := server.NewAndStartServer(conf, lg); err != nil {
		lg.Error("create server at ", port, err)
	} else {
		add(serv)
	}

}

func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one
		if config.ServerPort == 0 && config.Password == "" {
			lg.Error("must specify both port and password")
			return errors.New("not enough options")
		}
		port := strconv.Itoa(config.ServerPort)
		config.PortPassword = map[string]string{port: config.Password}
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			lg.Info("given port_password, ignore server_port and password option")
		}
	}
	return
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			updateConfig()
		} else {
			// is this going to happen?
			lg.Infof("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	servers = map[string]*server.Server{}

	servlock = &sync.Mutex{}

	fmt.Println("start")

	var cmdConfig ss.Config
	var printVer bool
	var core int
	var loglevel int

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 60, "connection timeout (in seconds)")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.IntVar((&loglevel), "d", int(loggo.ERROR), "print debug message")

	flag.Parse()

	var err error
	if lg, err = loggo.NewRollingDailyLogger("./log", "log.log"); err != nil {
		panic(err)
	}
	lg.LogLevel = loggo.LEVEL(loglevel)

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	config, err = ss.ParseConfig(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			panic(err)
		}
		config = &cmdConfig
	} else {
		if err = unifyPortPassword(config); err != nil {
			panic(err)
		}
		ss.UpdateConfig(config, &cmdConfig)
	}

	if config.Server != nil && reflect.TypeOf(config.Server).Kind() == reflect.String {
		serverIp = config.Server.(string)
	}

	for port, password := range config.PortPassword {
		conf := &server.Config{Ip: serverIp, Port: port, Password: password, Method: config.Method}
		if serv, err := server.NewAndStartServer(conf, lg); err != nil {
			lg.Error("create server at ", port, err)
		} else {
			add(serv)
		}
	}

	waitSignal()
}
