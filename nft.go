package main

// Delete vmap set

import (
	"bytes"
	"fmt"
	"os/exec"
	"reflect"
	"strings"

	"github.com/google/nftables"
	"github.com/sirupsen/logrus"
)

var (
	nft           *nftables.Conn
	lbTable       *nftables.Table
	lbChain       *nftables.Chain
	lbSet         *nftables.Set
	lbSetElements []nftables.SetElement
)

func initNFT() {
	// Connect to NFT
	nft = &nftables.Conn{}

	// Set Table Family
	var family nftables.TableFamily
	switch config.LBTable.Family {
	case "ip":
		family = nftables.TableFamilyIPv4
	case "ip6":
		family = nftables.TableFamilyIPv6
	case "inet":
		family = nftables.TableFamilyINet
	default:
		log.Fatalf("Unsupported LB Table Family %s", config.LBTable.Family)
	}

	// Declare Table
	lbTable = &nftables.Table{
		Name:   config.LBTable.Name,
		Family: family,
	}

	// Declare Chain
	lbChain = &nftables.Chain{
		Name:  config.LBChain,
		Table: lbTable,
	}

	// Get Current Rules
	rules, err := nft.GetRules(lbTable, lbChain)
	if err != nil {
		log.WithFields(logrus.Fields{
			"table": config.LBTable.Name,
			"chain": config.LBChain,
			"error": err,
		}).Error("Failed to retrieve NFT Rules")
	} else {
		log.Debugf("NFT Rules Found: %d", len(rules))
		for _, r := range rules {
			logRule(r)
		}
	}

	// Ensure table and chain exist
	addTable()
	addChain()

	// Prepare interface targets
	for _, i := range config.Interfaces {
		makeTarget(i)
	}
}

func updateNFT(ds string) string {
	// Connect to NFTables
	var err error
	nft, err = connectNFT()
	if err != nil {
		log.Errorf("Failed to connect to NFTables: %+v", err)
		return ""
	}

	// Set Rules
	var state string
	if ds == "all" {
		log.Debugf("Setting NFTables LB Rule to all")
		routeToAll()
		state = "all"
	} else {
		log.Infof("Asked to route to interface(s) %s", ds)
		routeToSubset(ds)
	}
	return state
}

func connectNFT() (*nftables.Conn, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Routes to only specific interfaces
func routeToSubset(ss string) {
	nifs := strings.Split(ss, "|")
	if len(nifs) < 1 {
		log.Error("Not enough interfaces provided, doing nothing")
		return
	}
	var ssNIFs []*vpsInterface
	for _, n := range nifs {
		for _, i := range config.Interfaces {
			if n == i.Name {
				ssNIFs = append(ssNIFs, i)
			}
		}
	}
	if len(ssNIFs) < 1 {
		log.Fatalf("Couldn't find matching interfaces for %s", nifs)
		return
	}
	// Create New Rule
	flushChainRules()
	addRuleToChain(ssNIFs)
}

// Creates a vmap based round-robin load balancer
// using ratios provided in interfaces[].ratio
func routeToAll() {
	flushChainRules()
	addRuleToChain(config.Interfaces)
}

// Add rule to all configured interfaces
func addRuleToChain(i []*vpsInterface) {
	// Create the rule
	ruleStr := makeRule(i)
	log.Debugf("Loading Rule %s", ruleStr)
	// Load the rule
	nftProg, err := exec.LookPath("nft")
	if err != nil {
		log.Fatalf("Failed to locate nft binary: %s", err)
	}
	nftCmd := exec.Command(nftProg, ruleStr)
	log.Tracef("Running %s", nftCmd.String())
	if out, err := nftCmd.Output(); err != nil {
		log.Fatalf("Failed to create load-balancing rule: %s", out, string(err.(*exec.ExitError).Stderr))
	}
}

// Generates a load-balancing rule given a list of interfaces
func makeRule(i []*vpsInterface) string {
	// Make sure we're not going to send packets to nowhere
	var mod uint8 = 10
	var ttlMod uint8
	for _, i := range i {
		ttlMod += uint8(i.Ratio)
	}
	if ttlMod != 10 {
		log.Debugf("Adjusting modulus, %d != 10", ttlMod)
		mod = ttlMod
	}

	// Prepare the rule
	var rule bytes.Buffer
	rule.WriteString(fmt.Sprintf("add rule %s %s %s ", config.LBTable.Family, config.LBTable.Name, config.LBChain))
	rule.WriteString(fmt.Sprintf("jhash ip saddr . ether saddr . meta l4proto . th sport mod %d vmap {", mod))
	var curMod uint8
	for _, nif := range i {
		rule.WriteString(fmt.Sprintf(" %d-%d : goto %s,", curMod, uint8(nif.Ratio)+(curMod-1), nif.Target))
		curMod += uint8(nif.Ratio)
	}
	rule.Truncate(rule.Len() - 1)
	rule.WriteRune(' ')
	rule.WriteRune('}')
	return rule.String()
}

// Sets up target chains for interface
func makeTarget(i *vpsInterface) {
	chain := &nftables.Chain{
		Name:  i.Target,
		Table: lbTable,
	}
	nft.AddChain(chain)
	commitAll()
	// If a mark is declared, manage the rule here
	if i.Mark != 0x0 {
		nft.FlushChain(chain)
		commitAll()
		var counter string
		if i.Counter {
			counter = " counter"
		}
		rule := fmt.Sprintf("add rule %s %s %s meta mark set %d%s return",
			config.LBTable.Family, lbTable.Name, i.Target, i.Mark, counter)
		log.Debugf("Loading interface mark rule: %s", rule)
		// Load the rule
		nftProg, err := exec.LookPath("nft")
		if err != nil {
			log.Fatalf("Failed to locate nft binary: %s", err)
		}
		nftCmd := exec.Command(nftProg, rule)
		log.Tracef("Running %s", nftCmd.String())
		if out, err := nftCmd.Output(); err != nil {
			log.Fatalf("Failed to create interface mark rule: %s", out, string(err.(*exec.ExitError).Stderr))
		}
	}
}

// Delete all rules in chain
func flushChainRules() {
	nft.FlushChain(lbChain)
	if err := nft.Flush(); err != nil {
		log.WithFields(logrus.Fields{
			"Table": lbChain.Table.Name,
			"Chain": lbChain.Name,
			"Error": err,
		}).Error("Failed to flush chain rules")
	}
}

// Add the table
func addTable() {
	nft.AddTable(lbTable)
	log.Debugf("Creating Table: %+v", lbTable)
	commitAll()
}

// Add the chain
func addChain() {
	nft.AddChain(lbChain)
	log.Debugf("Creating Chain: %+v", lbChain)
	commitAll()
}

// Log rule and its expressions
func logRule(r *nftables.Rule) {
	log.WithFields(logrus.Fields{
		"Table":    r.Table.Name,
		"Chain":    r.Chain.Name,
		"Position": r.Position,
		"Handle":   r.Handle,
	}).Trace("Rule")
	for i, e := range getRuleExpressions(r) {
		log.Tracef("\tExpression %d: %+v", i, e)
	}
}

// Convert expressions to strings
func getRuleExpressions(r *nftables.Rule) []string {
	var exprs []string
	for _, e := range r.Exprs {
		exprs = append(exprs, fmt.Sprintf("%s: %+v", reflect.TypeOf(e), e))
	}
	return exprs
}

// Commit rules
func commitAll() {
	if err := nft.Flush(); err != nil {
		log.Panicf("Error Flushing NFTables Config: %s", err)
	}
}
