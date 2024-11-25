// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/caffix/stringset"
	"github.com/openrdap/rdap"
	"github.com/openrdap/rdap/bootstrap"
	"github.com/openrdap/rdap/bootstrap/cache"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/property"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/relation"
	"github.com/owasp-amass/open-asset-model/url"
	"go.uber.org/ratelimit"
)

type rdapPlugin struct {
	name     string
	log      *slog.Logger
	client   *rdap.Client
	rlimit   ratelimit.Limiter
	autsys   *autsys
	autnum   *autnum
	netblock *netblock
	ipnet    *ipnet
	source   *et.Source
}

func NewRDAP() et.Plugin {
	return &rdapPlugin{
		name:   "RDAP",
		rlimit: ratelimit.New(10, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "RDAP",
			Confidence: 100,
		},
	}
}

func (rd *rdapPlugin) Name() string {
	return rd.name
}

func (rd *rdapPlugin) Start(r et.Registry) error {
	rd.log = r.Log().WithGroup("plugin").With("name", rd.name)

	outdir := config.OutputDirectory()
	if outdir == "" {
		return errors.New("failed to obtain the Amass output directory")
	}

	c := cache.NewDiskCache()
	if c == nil {
		return errors.New("failed to create the RDAP disk cache")
	}
	c.Dir = filepath.Join(outdir, ".openrdap")

	bs := &bootstrap.Client{Cache: c}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}
	bs.HTTP = &http.Client{
		Transport: transport,
	}
	httpClient := &http.Client{
		Transport: transport,
	}
	rd.client = &rdap.Client{
		HTTP:      httpClient,
		Bootstrap: bs,
	}

	rd.autsys = &autsys{
		name:   rd.name + "-Autsys-Handler",
		plugin: rd,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     rd,
		Name:       rd.autsys.name,
		Priority:   9,
		Transforms: []string{string(oam.AutnumRecord)},
		EventType:  oam.AutonomousSystem,
		Callback:   rd.autsys.check,
	}); err != nil {
		return err
	}

	rd.autnum = &autnum{
		name:   rd.name + "-Autnum-Handler",
		plugin: rd,
		transforms: []string{
			string(oam.FQDN),
			string(oam.URL),
			string(oam.ContactRecord),
			string(oam.Person),
			string(oam.Organization),
			string(oam.Location),
			string(oam.EmailAddress),
			string(oam.Phone),
		},
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     rd,
		Name:       rd.autnum.name,
		Priority:   1,
		Transforms: rd.autnum.transforms,
		EventType:  oam.AutnumRecord,
		Callback:   rd.autnum.check,
	}); err != nil {
		return err
	}

	rd.netblock = &netblock{
		name:   rd.name + "-Netblock-Handler",
		plugin: rd,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     rd,
		Name:       rd.netblock.name,
		Priority:   9,
		Transforms: []string{string(oam.IPNetRecord)},
		EventType:  oam.Netblock,
		Callback:   rd.netblock.check,
	}); err != nil {
		return err
	}

	rd.ipnet = &ipnet{
		name:   rd.name + "-IPNetwork-Handler",
		plugin: rd,
		transforms: []string{
			string(oam.FQDN),
			string(oam.URL),
			string(oam.ContactRecord),
			string(oam.Person),
			string(oam.Organization),
			string(oam.Location),
			string(oam.EmailAddress),
			string(oam.Phone),
		},
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     rd,
		Name:       rd.ipnet.name,
		Priority:   1,
		Transforms: rd.ipnet.transforms,
		EventType:  oam.IPNetRecord,
		Callback:   rd.ipnet.check,
	}); err != nil {
		return err
	}

	rd.log.Info("Plugin started")
	return nil
}

func (rd *rdapPlugin) Stop() {
	rd.log.Info("Plugin stopped")
}

func (rd *rdapPlugin) storeEntity(e *et.Event, level int, entity *rdap.Entity, asset *dbt.Entity, src *et.Source, m *config.Matches) []*support.Finding {
	var findings []*support.Finding

	roles := stringset.New(entity.Roles...)
	defer roles.Close()

	u := rd.getJSONLink(entity.Links)
	if u == nil {
		return nil
	}

	var rel string
	if roles.Has("registrant") && level == 1 {
		rel = "registrant"
	} else if roles.Has("administrative") {
		rel = "admin_contact"
	} else if roles.Has("abuse") {
		rel = "abuse_contact"
	} else if roles.Has("technical") {
		rel = "technical_contact"
	} else {
		return nil
	}

	cr, err := e.Session.Cache().CreateAsset(&contact.ContactRecord{DiscoveredAt: u.Raw})
	if err != nil || cr == nil {
		return nil
	}

	var name string
	switch v := asset.Asset.(type) {
	case *oamreg.AutnumRecord:
		name = "AutnumRecord: " + v.Handle
	case *oamreg.IPNetRecord:
		name = "IPNetRecord: " + v.Handle
	}

	findings = append(findings, &support.Finding{
		From:     asset,
		FromName: name,
		To:       cr,
		ToName:   "ContactRecord: " + u.Raw,
		Rel:      &relation.SimpleRelation{Name: rel},
	})

	if m.IsMatch(string(oam.URL)) {
		a, err := e.Session.Cache().CreateAsset(u)
		if err != nil {
			return nil
		}
		if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   &relation.SimpleRelation{Name: "url"},
			FromEntity: cr,
			ToEntity:   a,
		}); err == nil && edge != nil {
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		}
	}

	v := entity.VCard
	prop := v.GetFirst("kind")
	if prop == nil {
		return nil
	}

	name = v.Name()
	if kind := strings.Join(prop.Values(), " "); name != "" && kind == "individual" {
		if p := support.FullNameToPerson(name); p != nil && m.IsMatch(string(oam.Person)) {
			if a, err := e.Session.Cache().CreateAsset(p); err == nil && a != nil {
				if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
					Relation:   &relation.SimpleRelation{Name: "person"},
					FromEntity: cr,
					ToEntity:   a,
				}); err == nil && edge != nil {
					_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
						Source:     src.Name,
						Confidence: src.Confidence,
					})
				}
			}
		}
	} else if name != "" && m.IsMatch(string(oam.Organization)) {
		if a, err := e.Session.Cache().CreateAsset(&org.Organization{Name: name}); err == nil && a != nil {
			if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
				Relation:   &relation.SimpleRelation{Name: "organization"},
				FromEntity: cr,
				ToEntity:   a,
			}); err == nil && edge != nil {
				_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
					Source:     src.Name,
					Confidence: src.Confidence,
				})
			}
		}
	}
	if adr := v.GetFirst("adr"); adr != nil && m.IsMatch(string(oam.Location)) {
		if label, ok := adr.Parameters["label"]; ok {
			s := strings.Join(label, " ")

			addr := strings.Join(strings.Split(s, "\n"), " ")
			if loc := support.StreetAddressToLocation(addr); loc != nil {
				if a, err := e.Session.Cache().CreateAsset(loc); err == nil && a != nil {
					if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
						Relation:   &relation.SimpleRelation{Name: "location"},
						FromEntity: cr,
						ToEntity:   a,
					}); err == nil && edge != nil {
						_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
							Source:     src.Name,
							Confidence: src.Confidence,
						})
					}
				}
			}
		}
	}
	if email := support.EmailToOAMEmailAddress(v.Email()); email != nil && m.IsMatch(string(oam.EmailAddress)) {
		if a, err := e.Session.Cache().CreateAsset(email); err == nil && a != nil {
			if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
				Relation:   &relation.SimpleRelation{Name: "email"},
				FromEntity: cr,
				ToEntity:   a,
			}); err == nil && edge != nil {
				_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
					Source:     src.Name,
					Confidence: src.Confidence,
				})
			}
		}
	}
	if m.IsMatch(string(oam.Phone)) {
		if phone := support.PhoneToOAMPhone(v.Tel(), "", v.Country()); phone != nil {
			phone.Type = contact.PhoneTypeRegular
			if a, err := e.Session.Cache().CreateAsset(phone); err == nil && a != nil {
				if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
					Relation:   &relation.SimpleRelation{Name: "phone"},
					FromEntity: cr,
					ToEntity:   a,
				}); err == nil && edge != nil {
					_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
						Source:     src.Name,
						Confidence: src.Confidence,
					})
				}
			}
		}
		if fax := support.PhoneToOAMPhone(v.Fax(), "", v.Country()); fax != nil {
			fax.Type = contact.PhoneTypeFax
			if a, err := e.Session.Cache().CreateAsset(fax); err == nil && a != nil {
				if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
					Relation:   &relation.SimpleRelation{Name: "phone"},
					FromEntity: cr,
					ToEntity:   a,
				}); err == nil && edge != nil {
					_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
						Source:     src.Name,
						Confidence: src.Confidence,
					})
				}
			}
		}
	}

	level++
	for _, ent := range entity.Entities {
		findings = append(findings, rd.storeEntity(e, level, &ent, asset, rd.source, m)...)
	}
	return findings
}

func (rd *rdapPlugin) getJSONLink(links []rdap.Link) *url.URL {
	var url *url.URL
	for _, link := range links {
		if link.Type == "application/rdap+json" {
			url = support.RawURLToOAM(link.Href)
			break
		}
	}
	return url
}
