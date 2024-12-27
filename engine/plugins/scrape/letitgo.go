package scrape

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/property"
	"github.com/owasp-amass/open-asset-model/relation"
	"go.uber.org/ratelimit"
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
			Name:       "LetItGo",
			Confidence: 100,
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

func (l *letitgo) check(e *et.Event) error {
	entities, err := l.query(e, e.Entity.Asset.(*domain.FQDN).Name, l.source)
	if err != nil {
		l.log.Error("Query failed", "error", err)
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, l.source)

	if len(entities) > 0 {
		l.process(e, entities, l.source)
	}
	return nil
}

func (l *letitgo) query(e *et.Event, name string, source *et.Source) ([]*dbt.Entity, error) {
	if e == nil || e.Session == nil {
		l.log.Info("Invalid Event Or Session")
		return nil, fmt.Errorf("invalid event or session")
	}

	l.rlimit.Take()

	subs := stringset.New()
	defer subs.Close()

	soapEnvelope := []byte(strings.TrimSpace(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Header>
	<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
	<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
	<a:ReplyTo>
		<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
	</a:ReplyTo>
</soap:Header>
<soap:Body>
	<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
		<Request>
			<Domain>%s</Domain>
		</Request>
	</GetFederationInformationRequestMessage>
</soap:Body>
</soap:Envelope>`, name)))

	l.log.Info("SOAP Request", "request", string(soapEnvelope))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := postSOAP(ctx, "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc", soapEnvelope)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	l.log.Info("SOAP Response", "response", string(responseBody))

	var envelope struct {
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

	if err := xml.NewDecoder(bytes.NewReader(responseBody)).Decode(&envelope); err != nil {
		return nil, err
	}

	for _, domain := range envelope.Body.GetFederationInformationResponseMessage.Response.Domains.Domain {
		subs.Insert(strings.ToLower(domain))
	}

	if subs.Len() == 0 {
		return nil, fmt.Errorf("no valid domains found")
	}

	return l.store(e, subs.Slice(), l.source), nil
}

func (l *letitgo) store(e *et.Event, names []string, src *et.Source) []*dbt.Entity {
	entities := support.StoreFQDNsWithSource(e.Session, names, l.source, l.name, l.name+"-Handler")

	// Create edges between the event entity and the new FQDNs
	for _, entity := range entities {
		if entity == nil {
			e.Session.Log().Error("Entity is nil")
			continue
		}
		if e.Entity == nil {
			e.Session.Log().Error("Event entity is nil")
			continue
		}
		edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   &relation.SimpleRelation{Name: "associated_with"},
			FromEntity: e.Entity,
			ToEntity:   entity,
		})
		if err != nil {
			e.Session.Log().Error("Failed to create edge", "error", err)
			continue
		}
		if edge == nil {
			e.Session.Log().Error("Edge is nil")
			continue
		}
		_, err = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
			Source:     l.source.Name,
			Confidence: l.source.Confidence,
		})
		if err != nil {
			e.Session.Log().Error("Failed to create edge property", "error", err)
		}
	}

	return entities
}

func (l *letitgo) process(e *et.Event, assets []*dbt.Entity, source *et.Source) {
	support.ProcessFQDNsWithSource(e, assets, l.source)
}

func (l *letitgo) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), l.source, since)
}

// postSOAP sends the SOAP request to the specified URL
func postSOAP(ctx context.Context, url string, envelope []byte) (*http.Response, error) {
	request, err := http.NewRequest("POST", url, bytes.NewReader(envelope))
	tr := &http.Transport{
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "text/xml; charset=utf-8")
	request.Header.Set("SOAPAction", `"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"`)
	request.Header.Set("User-Agent", "AutodiscoverClient")
	return client.Do(request)
}
