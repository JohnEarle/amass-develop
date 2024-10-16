// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/utils"
	"github.com/owasp-amass/amass/v4/utils/afmt"
	assetdb "github.com/owasp-amass/asset-db"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

const subsUsageMsg = "subs [options] -d domain"

type subsArgs struct {
	Domains *stringset.Set
	Enum    int
	Options struct {
		DemoMode        bool
		IPs             bool
		IPv4            bool
		IPv6            bool
		ASNTableSummary bool
		DiscoveredNames bool
		NoColor         bool
		ShowAll         bool
		Silent          bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
		TermOut    string
	}
}

type outLookup map[string]*utils.Output

func runSubsCommand(clArgs []string) {
	var args subsArgs
	var help1, help2 bool
	subsCommand := flag.NewFlagSet("subs", flag.ContinueOnError)

	args.Domains = stringset.New()
	defer args.Domains.Close()

	subsBuf := new(bytes.Buffer)
	subsCommand.SetOutput(subsBuf)

	subsCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	subsCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	subsCommand.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	subsCommand.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	subsCommand.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	subsCommand.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	subsCommand.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	subsCommand.BoolVar(&args.Options.ASNTableSummary, "summary", false, "Print Just ASN Table Summary")
	subsCommand.BoolVar(&args.Options.DiscoveredNames, "names", false, "Print Just Discovered Names")
	subsCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	subsCommand.BoolVar(&args.Options.ShowAll, "show", false, "Print the results for the enumeration index + domains provided")
	subsCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	subsCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file. Additional details below")
	subsCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	subsCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	subsCommand.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")

	var usage = func() {
		afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), subsUsageMsg)
		subsCommand.PrintDefaults()
		afmt.G.Fprintln(color.Error, subsBuf.String())
	}

	if len(clArgs) < 1 {
		usage()
		return
	}
	if err := subsCommand.Parse(clArgs); err != nil {
		afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		usage()
		return
	}
	if args.Options.NoColor {
		color.NoColor = true
	}
	if args.Options.Silent {
		color.Output = io.Discard
		color.Error = io.Discard
	}
	if args.Options.IPs {
		args.Options.IPv4 = true
		args.Options.IPv6 = true
	}
	if args.Filepaths.Domains != "" {
		list, err := config.GetListFromFile(args.Filepaths.Domains)
		if err != nil {
			afmt.R.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			return
		}
		args.Domains.InsertMany(list...)
	}

	cfg := config.NewConfig()
	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
		if args.Filepaths.Directory == "" {
			args.Filepaths.Directory = cfg.Dir
		}
		if args.Domains.Len() == 0 {
			args.Domains.InsertMany(cfg.Domains()...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		afmt.R.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}

	db := utils.OpenGraphDatabase(cfg)
	if db == nil {
		afmt.R.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}

	if args.Options.ShowAll {
		args.Options.DiscoveredNames = true
		args.Options.ASNTableSummary = true
	}
	if !args.Options.DiscoveredNames && !args.Options.ASNTableSummary {
		usage()
		return
	}

	var asninfo bool
	if args.Options.ASNTableSummary {
		asninfo = true
	}

	showData(&args, asninfo, db)
}

func showData(args *subsArgs, asninfo bool, db *assetdb.AssetDB) {
	var total int
	var err error
	var outfile *os.File
	domains := args.Domains.Slice()

	if args.Filepaths.TermOut != "" {
		outfile, err = os.OpenFile(args.Filepaths.TermOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			afmt.R.Fprintf(color.Error, "Failed to open the text output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			_ = outfile.Sync()
			_ = outfile.Close()
		}()
		_ = outfile.Truncate(0)
		_, _ = outfile.Seek(0, 0)
	}

	var cache *utils.ASNCache
	if asninfo {
		cache = utils.NewASNCache()
		if err := utils.FillCache(cache, db); err != nil {
			afmt.R.Printf("Failed to populate the ASN cache: %v\n", err)
			return
		}
	}

	names := getNames(db, domains, asninfo)
	if len(names) != 0 && (asninfo || args.Options.IPv4 || args.Options.IPv6) {
		names = addAddresses(db, names, asninfo, cache)
	}

	asns := make(map[int]*utils.ASNSummaryData)
	for _, out := range names {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}

		if args.Options.IPv4 || args.Options.IPv6 {
			out.Addresses = afmt.DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
		}

		if l := len(out.Addresses); (args.Options.IPv4 || args.Options.IPv6) && l == 0 {
			continue
		} else if l > 0 {
			afmt.UpdateSummaryData(out, asns)
		}

		total++
		name, ips := afmt.OutputLineParts(out, args.Options.IPv4 || args.Options.IPv6, args.Options.DemoMode)
		if ips != "" {
			ips = " " + ips
		}

		if args.Options.DiscoveredNames {
			var written bool
			if outfile != nil {
				fmt.Fprintf(outfile, "%s%s\n", name, ips)
				written = true
			}
			if !written {
				fmt.Fprintf(color.Output, "%s%s\n", afmt.Green(name), afmt.Yellow(ips))
			}
		}
	}

	if total == 0 {
		afmt.R.Println("No names were discovered")
		return
	}
	if args.Options.ASNTableSummary {
		var out io.Writer
		status := color.NoColor

		if outfile != nil {
			out = outfile
			color.NoColor = true
		} else if args.Options.ShowAll {
			out = color.Error
		} else {
			out = color.Output
		}

		afmt.FprintEnumerationSummary(out, total, asns, args.Options.DemoMode)
		color.NoColor = status
	}
}

func getNames(db *assetdb.AssetDB, domains []string, asninfo bool) []*utils.Output {
	if len(domains) == 0 {
		return nil
	}

	qtime := time.Time{}
	filter := stringset.New()
	defer filter.Close()

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, &domain.FQDN{Name: d})
	}

	assets, err := db.FindByScope(fqdns, qtime)
	if err != nil {
		return nil
	}

	var names []*utils.Output
	for _, a := range assets {
		if n, ok := a.Asset.(*domain.FQDN); ok && !filter.Has(n.Name) {
			names = append(names, &utils.Output{Name: n.Name})
			filter.Insert(n.Name)
		}
	}
	return names
}

func addAddresses(db *assetdb.AssetDB, names []*utils.Output, asninfo bool, cache *utils.ASNCache) []*utils.Output {
	var namestrs []string
	lookup := make(outLookup, len(names))
	for _, n := range names {
		lookup[n.Name] = n
		namestrs = append(namestrs, n.Name)
	}

	qtime := time.Time{}
	if pairs, err := utils.NamesToAddrs(db, qtime, namestrs...); err == nil {
		for _, p := range pairs {
			addr := p.Addr.Address.String()

			if p.FQDN.Name == "" || addr == "" {
				continue
			}
			if o, found := lookup[p.FQDN.Name]; found {
				o.Addresses = append(o.Addresses, utils.AddressInfo{Address: net.ParseIP(addr)})
			}
		}
	}

	if !asninfo || cache == nil {
		var output []*utils.Output
		for _, o := range lookup {
			if len(o.Addresses) > 0 {
				output = append(output, o)
			}
		}
		return output
	}
	return addInfrastructureInfo(lookup, cache)
}

func domainNameInScope(name string, scope []string) bool {
	var discovered bool

	n := strings.ToLower(strings.TrimSpace(name))
	for _, d := range scope {
		d = strings.ToLower(d)

		if n == d || strings.HasSuffix(n, "."+d) {
			discovered = true
			break
		}
	}

	return discovered
}

func addInfrastructureInfo(lookup outLookup, cache *utils.ASNCache) []*utils.Output {
	output := make([]*utils.Output, 0, len(lookup))

	for _, o := range lookup {
		var newaddrs []utils.AddressInfo

		for _, a := range o.Addresses {
			i := cache.AddrSearch(a.Address.String())
			if i == nil {
				continue
			}

			_, netblock, _ := net.ParseCIDR(i.Prefix)
			newaddrs = append(newaddrs, utils.AddressInfo{
				Address:     a.Address,
				ASN:         i.ASN,
				CIDRStr:     i.Prefix,
				Netblock:    netblock,
				Description: i.Description,
			})
		}

		o.Addresses = newaddrs
		if len(o.Addresses) > 0 {
			output = append(output, o)
		}
	}
	return output
}
