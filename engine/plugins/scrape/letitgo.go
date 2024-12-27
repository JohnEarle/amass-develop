package scrape

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"errors"
	"net/http"
	"strings"
	"time"
	"os"

	"github.com/caffix/stringset"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	"go.uber.org/ratelimit"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
)

type letitgo struct {
	name   string
	rlimit ratelimit.Limiter
	log    *slog.Logger
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
	
	l.log = slog.New(slog.NewTextHandler(os.Stdout, nil)).WithGroup("plugin").With("name", l.name)
	
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       l,
		Name:         l.name + "-Handler",
		Priority:     5,
		MaxInstances: 5,
		EventType:    oam.FQDN,
		Callback:     l.check,
	}); err != nil {
		return err
	}
	l.log.Info("LetItGo Plugin started")
	return nil
}

// Stop implements the Stop method required by et.Plugin
func (l *letitgo) Stop() {
	l.log.Info("LetItGo Plugin stopped")
}

func (l *letitgo) process(e *et.Event, assets []*dbt.Entity, source *et.Source) {
	support.ProcessFQDNsWithSource(e, assets, l.source)
}

// Query performs the scraping operation
func (l *letitgo) query(e *et.Event, name string, source *et.Source) ([]*dbt.Entity, error) {
	if e == nil || e.Session == nil {
		l.log.Info("Invalid Event Or Session")
		return nil, fmt.Errorf("invalid event or session")
	}

	l.rlimit.Take()

	subs := stringset.New()
	defer subs.Close()

	soapEnvelope := fmt.Sprintf(`<?xml version="1.0"?>
		<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
		<soap:Body><Domain>%s</Domain></soap:Body></soap:Envelope>`, name)

	url := "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
	l.log.Info("Sending SOAP Request", "envelope", soapEnvelope)
	resp, err := postSOAP(context.TODO(), url, soapEnvelope)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parsed Response
	err = xml.NewDecoder(resp.Body).Decode(&parsed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse XML: %v", err)
	}

	for _, d := range parsed.Body.GetFederationInformationResponseMessage.Response.Domains.Domain {
		if strings.HasSuffix(d, "onmicrosoft.com") {
			continue
		}
		bareDomain, err := publicsuffix.EffectiveTLDPlusOne(d)
		if err == nil {
			l.log.Info(bareDomain)
			subs.Insert(strings.ToLower(bareDomain))
		}
	}

	if subs.Len() == 0 {
		return nil, fmt.Errorf("no valid domains found")
	}

	return l.store(e, subs.Slice(), l.source), nil
}

func (l *letitgo) store(e *et.Event, names []string, src *et.Source) []*dbt.Entity {
    return support.StoreFQDNsWithSource(e.Session, names, l.source, l.name, l.name+"-Handler")
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

func (l *letitgo) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if f, ok := a.(*domain.FQDN); !ok || f == nil || !strings.EqualFold(fqdn.Name, f.Name) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), l.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, l.source, since) {
		names = append(names, l.lookup(e, fqdn.Name, since)...)
	} else {
		entities, err := l.query(e, fqdn.Name, l.source)
		if err != nil {
			l.log.Error("Query failed", "error", err)
			return nil
		}
		names = append(names, entities...)
		support.MarkAssetMonitored(e.Session, e.Entity, l.source)
	}

	if len(names) > 0 {
		l.process(e, names, l.source)
	}
	return nil
}


func (l *letitgo) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), l.source, since)
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
