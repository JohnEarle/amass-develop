package scrape

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdomain "github.com/owasp-amass/open-asset-model/domain"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	"go.uber.org/ratelimit"
)

type letitgo struct {
	name   string
	rlimit ratelimit.Limiter
	source *et.Source
}

// NewLetItGo initializes the LetItGo plugin
func NewLetItGo() et.Plugin {
	return &letitgo{
		name:   "LetItGo",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
		source: &et.Source{
			Name: "LetItGo",
		},
	}
}

// Name returns the plugin name
func (l *letitgo) Name() string {
	return l.name
}

// Start registers the plugin with the Amass engine
func (l *letitgo) Start(r et.Registry) error {
	return r.RegisterHandler(&et.Handler{
		Plugin:       l,
		Name:         l.name + "-Handler",
		Priority:     5,
		MaxInstances: 5,
		EventType:    "dns",
		Callback:     l.handleEvent,
	})
}

// Stop implements the Stop method required by et.Plugin
func (l *letitgo) Stop() {
	// Perform any necessary cleanup here
}

// HandleEvent wraps Run for event-based callbacks
func (l *letitgo) handleEvent(e *et.Event) error {
	if e == nil || e.Session == nil {
		return fmt.Errorf("invalid event or session")
	}
	return l.Run(context.TODO(), e)
}

// Run executes the scraping logic
func (l *letitgo) Run(ctx context.Context, e *et.Event) error {
	l.rlimit.Take()

	bareDomains := make(map[string]bool)
	retry := true
	for retry {
		soapEnvelope := fmt.Sprintf(`<?xml version="1.0"?>
			<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
			<soap:Body><Domain>%s</Domain></soap:Body></soap:Envelope>`, e.Name)

		url := "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
		resp, err := postSOAP(ctx, url, soapEnvelope)
		if err != nil {
			return err
		}

		var parsed Response
		err = xml.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to parse XML: %v", err)
		}

		for _, d := range parsed.Body.GetFederationInformationResponseMessage.Response.Domains.Domain {
			if strings.HasSuffix(d, "onmicrosoft.com") {
				continue
			}
			bareDomain, err := publicsuffix.EffectiveTLDPlusOne(d)
			if err == nil {
				bareDomains[strings.ToLower(bareDomain)] = true
			}
		}
		retry = false
	}

	for bareDomain := range bareDomains {
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdomain.FQDN{Name: bareDomain}, 0); conf > 0 {
			entity, err := e.Session.Cache().CreateAsset(&oamdomain.FQDN{Name: bareDomain})
			if err == nil && entity != nil {
				newEvent := &et.Event{
					Name:       bareDomain,
					Entity:     entity,
					Dispatcher: e.Dispatcher,
					Session:    e.Session,
				}
				if err := newEvent.Dispatcher.DispatchEvent(newEvent); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Response represents the XML response structure
type Response struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		GetFederationInformationResponseMessage struct {
			Response struct {
				Domains struct {
					Domain []string `xml:"Domain"`
				} `xml:"Domains"`
			} `xml:"Response"`
		} `xml:"GetFederationInformationResponseMessage"`
	} `xml:"Body"`
}

// postSOAP sends the SOAP request to the specified URL
func postSOAP(ctx context.Context, url, envelope string) (*http.Response, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(envelope))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "text/xml; charset=utf-8")
	request.Header.Set("SOAPAction", "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation")
	request.Header.Set("User-Agent", "AutodiscoverClient")
	return client.Do(request)
}
