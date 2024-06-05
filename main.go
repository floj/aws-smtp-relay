package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/blueimp/aws-smtp-relay/internal/auth"
	"github.com/blueimp/aws-smtp-relay/internal/relay"
	sesrelay "github.com/blueimp/aws-smtp-relay/internal/relay/ses"
	"github.com/mhale/smtpd"
)

var (
	addr      = flag.String("listen", ":1025", "TCP listen address")
	name      = flag.String("smtp-name", "AWS SMTP Relay", "SMTP service name")
	host      = flag.String("host", "", "Server hostname")
	certFile  = flag.String("tls-cert", "", "TLS cert file")
	keyFile   = flag.String("tls-key", "", "TLS key file")
	startTLS  = flag.Bool("require-starttls", false, "Require TLS via STARTTLS extension")
	onlyTLS   = flag.Bool("tls-only", false, "Listen for incoming TLS connections only")
	ips       = flag.String("allow-ips", "", "Allowed client IPs (comma-separated)")
	user      = flag.String("user", "", "Authentication username")
	allowFrom = flag.String("allow-from", "", "Allowed sender emails regular expression")
	denyTo    = flag.String("deny-to", "", "Denied recipient emails regular expression")
	region    = flag.String("region", os.Getenv("AWS_REGION"), "aws region")
)

var ipMap map[string]bool
var bcryptHash []byte
var password []byte
var relayClient relay.Client

func server() (srv *smtpd.Server, err error) {
	authMechs := make(map[string]bool)
	if *user != "" && len(bcryptHash) > 0 && len(password) == 0 {
		authMechs["CRAM-MD5"] = false
	}
	srv = &smtpd.Server{
		Addr:         *addr,
		Handler:      relayClient.Send,
		Appname:      *name,
		Hostname:     *host,
		TLSRequired:  *startTLS,
		TLSListener:  *onlyTLS,
		AuthRequired: ipMap != nil || *user != "",
		AuthHandler:  auth.New(ipMap, *user, bcryptHash, password).Handler,
		AuthMechs:    authMechs,
	}
	if *certFile != "" && *keyFile != "" {
		keyPass := os.Getenv("TLS_KEY_PASS")
		if keyPass != "" {
			err = srv.ConfigureTLSWithPassphrase(*certFile, *keyFile, keyPass)
		} else {
			err = srv.ConfigureTLS(*certFile, *keyFile)
		}
	}
	return
}

func configure() error {
	var allowFromRegExp *regexp.Regexp
	var denyToRegExp *regexp.Regexp
	var err error
	if *allowFrom != "" {
		allowFromRegExp, err = regexp.Compile(*allowFrom)
		if err != nil {
			return errors.New("Allowed sender emails: " + err.Error())
		}
	}
	if *denyTo != "" {
		denyToRegExp, err = regexp.Compile(*denyTo)
		if err != nil {
			return errors.New("Denied recipient emails: " + err.Error())
		}
	}
	relayClient, err = sesrelay.New(allowFromRegExp, denyToRegExp, *region)
	if err != nil {
		return fmt.Errorf("failed to create SES relay client: %w", err)
	}
	if *ips != "" {
		ipMap = make(map[string]bool)
		for _, ip := range strings.Split(*ips, ",") {
			ipMap[ip] = true
		}
	}
	bcryptHash = []byte(os.Getenv("BCRYPT_HASH"))
	password = []byte(os.Getenv("PASSWORD"))
	return nil
}

func main() {
	flag.Parse()
	var srv *smtpd.Server
	err := configure()
	if err == nil {
		srv, err = server()
		if err == nil {
			err = srv.ListenAndServe()
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
