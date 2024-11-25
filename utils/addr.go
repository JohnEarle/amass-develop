// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"errors"
	"time"

	"github.com/caffix/stringset"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/relation"
)

func ReadASPrefixes(db *assetdb.AssetDB, asn int, since time.Time) []string {
	var prefixes []string

	fqdns, err := db.FindByContent(&network.AutonomousSystem{Number: asn}, since)
	if err != nil || len(fqdns) != 1 {
		return prefixes
	}
	fqdn := fqdns[0]

	if edges, err := db.Repo.OutgoingEdges(fqdn, since, "announces"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := db.Repo.FindEntityById(edge.ToEntity.ID); err != nil {
				continue
			} else if netblock, ok := a.Asset.(*network.Netblock); ok {
				prefixes = append(prefixes, netblock.CIDR.String())
			}
		}
	}

	return prefixes
}

type NameAddrPair struct {
	FQDN *domain.FQDN
	Addr *network.IPAddress
}

func NamesToAddrs(db *assetdb.AssetDB, since time.Time, names ...string) ([]*NameAddrPair, error) {
	var fqdns []*dbt.Entity
	for _, name := range names {
		if ents, err := db.Repo.FindEntityByContent(&domain.FQDN{Name: name}, since); err == nil && len(ents) == 1 {
			fqdns = append(fqdns, ents[0])
		}
	}

	var results []*NameAddrPair
	// get the IPs associated with SRV, NS, and MX records
loop:
	for _, fqdn := range fqdns {
		if edges, err := db.Repo.OutgoingEdges(fqdn, since, "dns_record"); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				switch v := edge.Relation.(type) {
				case *relation.BasicDNSRelation:
					if v.Header.RRType == 1 || v.Header.RRType == 28 {
						if ip, err := getAddr(db.Repo, edge.ToEntity, since); err == nil {
							results = append(results, &NameAddrPair{
								FQDN: fqdn.Asset.(*domain.FQDN),
								Addr: ip,
							})
							continue loop
						}
					} else if v.Header.RRType == 5 {
						if ip, err := cnameQuery(db.Repo, edge.ToEntity, since); err == nil {
							results = append(results, &NameAddrPair{
								FQDN: fqdn.Asset.(*domain.FQDN),
								Addr: ip,
							})
							continue loop
						}
					}
				case *relation.PrefDNSRelation:
					if v.Header.RRType == 2 || v.Header.RRType == 15 {
						if ip, err := oneMoreName(db.Repo, edge.ToEntity, since); err == nil {
							results = append(results, &NameAddrPair{
								FQDN: fqdn.Asset.(*domain.FQDN),
								Addr: ip,
							})
							continue loop
						}
					}
				case *relation.SRVDNSRelation:
					if v.Header.RRType == 33 {
						if ip, err := oneMoreName(db.Repo, edge.ToEntity, since); err == nil {
							results = append(results, &NameAddrPair{
								FQDN: fqdn.Asset.(*domain.FQDN),
								Addr: ip,
							})
							continue loop
						}
					}
				}
			}
		}
	}

	return results, nil
}

func getAddr(db repository.Repository, ip *dbt.Entity, since time.Time) (*network.IPAddress, error) {
	if entity, err := db.FindEntityById(ip.ID); err == nil && entity != nil {
		if ip, ok := entity.Asset.(*network.IPAddress); ok {
			return ip, nil
		}
	}
	return nil, errors.New("failed to extract the IP address")
}

func oneMoreName(db repository.Repository, fqdn *dbt.Entity, since time.Time) (*network.IPAddress, error) {
	if edges, err := db.OutgoingEdges(fqdn, since, "dns_record"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if rel, ok := edge.Relation.(*relation.BasicDNSRelation); ok && (rel.Header.RRType == 1 || rel.Header.RRType == 28) {
				return getAddr(db, edge.ToEntity, since)
			}
		}
	}
	return nil, errors.New("failed to traverse the FQDN")
}

func cnameQuery(db repository.Repository, fqdn *dbt.Entity, since time.Time) (*network.IPAddress, error) {
	set := stringset.New()
	defer set.Close()

	next := fqdn
loop:
	for i := 0; i < 10; i++ {
		n, err := db.FindEntityById(next.ID)
		if err != nil || set.Has(n.Asset.Key()) {
			break
		}
		set.Insert(n.Asset.Key())

		if edges, err := db.OutgoingEdges(n, since, "dns_record"); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if rel, ok := edge.Relation.(*relation.BasicDNSRelation); ok {
					if rel.Header.RRType == 1 || rel.Header.RRType == 28 {
						return getAddr(db, edge.ToEntity, since)
					} else if rel.Header.RRType == 5 {
						next = edge.ToEntity
						continue loop
					}
				}
			}
		}
	}

	return nil, errors.New("failed to traverse the aliases")
}
