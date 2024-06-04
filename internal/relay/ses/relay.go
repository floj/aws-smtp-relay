package relay

import (
	"context"
	"fmt"
	"net"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/blueimp/aws-smtp-relay/internal/relay"
)

// Client implements the Relay interface.
type Client struct {
	sesAPI          *ses.Client
	allowFromRegExp *regexp.Regexp
	denyToRegExp    *regexp.Regexp
}

// Send uses the client SESAPI to send email data
func (c Client) Send(origin net.Addr, from string, to []string, data []byte) error {
	allowedRecipients, deniedRecipients, err := relay.FilterAddresses(from, to, c.allowFromRegExp, c.denyToRegExp)
	if err != nil {
		relay.Log(origin, from, deniedRecipients, err)
	}
	if len(allowedRecipients) > 0 {
		_, err := c.sesAPI.SendRawEmail(context.TODO(), &ses.SendRawEmailInput{
			Source:       &from,
			Destinations: allowedRecipients,
			RawMessage:   &types.RawMessage{Data: data},
		})
		relay.Log(origin, from, allowedRecipients, err)
		if err != nil {
			return err
		}
	}
	return err
}

// New creates a new client with a session.
func New(allowFromRegExp *regexp.Regexp, denyToRegExp *regexp.Regexp, region string) (*Client, error) {
	if region == "" {
		return nil, fmt.Errorf("required env var AWS_REGION not set")
	}
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS SDK config, %w", err)
	}
	return &Client{
		sesAPI:          ses.NewFromConfig(cfg),
		allowFromRegExp: allowFromRegExp,
		denyToRegExp:    denyToRegExp,
	}, nil
}
