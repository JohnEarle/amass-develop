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
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	"go.uber.org/ratelimit"
)

type letitgo struct {
	name   string
	rlimit ratelimit.Limiter
	source *et.Source
}

func NewLetItGo() et.Plugin {
	return &letitgo{
		name:   "LetItGo",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "LetItGo",
			Description: "Scrapes Outlook Autodiscover for domain information",
		},
	}
}

func (l *letitgo) Name() string {
	return l.name
}

func (l *letitgo) Run(ctx context.Context, sess et.Session, domain string) error {
	l.rlimit.Take()
	
	bareDomains := make(map[string]bool)

	retry := true
	for retry {
		soapEnvelope := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
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
</soap:Envelope>`, domain)

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
			if err != nil {
				continue
			}
			bareDomains[strings.ToLower(bareDomain)] = true
		}

		if len(bareDomains) == 0 && !strings.HasSuffix(domain, "onmicrosoft.com") {
			fmt.Println("Retrying with onmicrosoft.com suffix")
			tld, _ := publicsuffix.EffectiveTLDPlusOne(domain)
			parts := strings.Split(tld, ".")
			if len(parts) > 1 {
				domain = fmt.Sprintf("%s.onmicrosoft.com", parts[len(parts)-2])
				continue
			}
		}
		retry = false
	}

	for bareDomain := range bareDomains {
		if sess.InScope(bareDomain) {
			sess.NewName(&et.DNSRequest{
				Name:       bareDomain,
				Domain:     domain,
				Tag:        l.source.Name,
				Source:     l.source.Name,
				Confidence: 90,  // High confidence for discovered domains
			})
		}
	}

	return nil
}

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
