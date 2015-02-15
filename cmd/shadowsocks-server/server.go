package main

import (
	"flag"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/fym201/shadowsocks-go/server"
	ss "github.com/fym201/shadowsocks-go/shadowsocks"

	"fmt"

	"github.com/fym201/loggo"
)

var configFile string
var config *ss.Config
var lg *loggo.Logger
var shadowserver *server.Server

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

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
		ss.UpdateConfig(config, &cmdConfig)
	}

	if shadowserver, err = server.NewServer(config, lg); err != nil {
		panic(err)
	}

	if err = shadowserver.Start(); err != nil {
		panic(err)
	}

	waitSignal()
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			shadowserver.UpdateConfig(config)
		} else {
			// is this going to happen?
			lg.Infof("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}
