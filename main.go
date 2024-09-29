package main

import (
	"bufio"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	ExitOK = iota
	ExitArgsError
	ExitFileError
	ExitDigError
	ExitWhoisError
	ExitCSVError
	ExitJSONError
	ExitYAMLError
)

//go:embed dns.txt
var strDNS string

//go:embed contacts.yaml
var strContacts string

var (
	reIP          = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	reEmail       = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	reDomain      = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	abuseContacts map[string]string
	dnsServers    []string
	domains       []string
	abuseCache    sync.Map
	dnsIndex      int
	dnsLock       sync.Mutex
	exitMessages  = map[int]string{
		ExitOK:         "",
		ExitArgsError:  "args error",
		ExitFileError:  "file error",
		ExitDigError:   "dig error",
		ExitWhoisError: "whois error",
		ExitCSVError:   "csv error",
		ExitJSONError:  "json error",
		ExitYAMLError:  "yaml error",
	}
)

type DomainInfo struct {
	Domain       string
	IP           string
	Hostname     string
	AbuseContact string
}

func die(msg string, code int, output string, err error) {
	name := strings.ToUpper(exitMessages[code])
	if strings.TrimSpace(msg) != "" {
		fmt.Printf("[%s] %s\n", name, msg)
	}
	if err != nil && err.Error() != "" {
		fmt.Printf("[%s] %s\n", name, err.Error())
	}
	if strings.TrimSpace(output) != "" {
		fmt.Printf("[%s] Output was:\n%s\n", name, output)
	}
	os.Exit(code)
}

func getNextDNS() string {
	dnsLock.Lock()
	defer dnsLock.Unlock()
	server := dnsServers[dnsIndex]
	dnsIndex = (dnsIndex + 1) % len(dnsServers)
	return server
}

func sanitizeDomain(domain string) string {
	if !reDomain.MatchString(domain) {
		return ""
	}
	return domain
}

func sanitizeIP(ip string) string {
	if !reIP.MatchString(ip) {
		return ""
	}
	return ip
}

func sanitizeDNS(dns string) string {
	if !reIP.MatchString(dns) {
		return ""
	}
	return dns
}

func lookupIP(domain string) string {
	domain = sanitizeDomain(domain)
	server := sanitizeDNS(getNextDNS())
	cmd := exec.Command("dig", "+short", domain, "@"+server)
	output, err := cmd.Output()
	if err != nil {
		if strings.Contains(err.Error(), "exit status 10") {
			return "" // none found
		}
		die("IP lookup", ExitDigError, string(output), err)
	}
	ips := strings.Fields(string(output))
	if len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		ip = sanitizeIP(ip)
		if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "192.168.") {
			continue // Skip invalid, loopback and private IPs
		}
		return ip
	}
	return ""
}

func lookupHostname(ip string) string {
	ip = sanitizeIP(ip)
	server := sanitizeDNS(getNextDNS())
	cmd := exec.Command("dig", "+short", "-x", ip, "@"+server)
	output, err := cmd.Output()
	if err != nil {
		if strings.Contains(err.Error(), "exit status 10") {
			return "" // none found
		}
		die("Hostname lookup failed", ExitDigError, string(output), err)
	}
	hostnames := strings.Fields(string(output))
	if len(hostnames) == 0 {
		return ""
	}
	return strings.TrimSuffix(hostnames[0], ".")
}

func lookupAbuseContact(ip string, hostname string) string {
	ip = sanitizeIP(ip)
	hostname = sanitizeDomain(hostname)

	if contact, found := abuseCache.Load(ip); found {
		return contact.(string)
	}

	for knownHost, contact := range abuseContacts {
		if strings.HasSuffix(hostname, knownHost) || ip == knownHost {
			abuseCache.Store(ip, contact)
			return contact
		}
	}

	abuseContact := lookupWhoisAbuse(ip)
	abuseCache.Store(ip, abuseContact)
	return abuseContact
}

func lookupWhoisAbuse(ip string) string {
	ip = sanitizeIP(ip)

	cmd := exec.Command("timeout", "5", "whois", "-b", ip)
	output, err := cmd.Output()
	if err != nil {
		if strings.Contains(err.Error(), "exit status 124") {
			return string(output)
		}
		die("Abuse contact lookup (brief) failed.", ExitWhoisError, string(output), err)
	}

	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "Abuse") || strings.Contains(line, "abuse") {
			email := extractEmail(line)
			if email != "" {
				return email
			}
		}
	}

	// Maybe the extended output contains a record
	cmd = exec.Command("timeout", "5", "whois", ip)
	output, err = cmd.Output()
	if err != nil {
		if !strings.Contains(err.Error(), "exit status 124") {
			die("Full WHOIS lookup failed.", ExitWhoisError, string(output), err)
		}
	}

	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "Abuse") || strings.Contains(line, "abuse") {
			email := extractEmail(line)
			if email != "" {
				return email
			}

		}
	}

	return ""
}

func extractEmail(text string) string {
	matches := reEmail.FindAllString(text, -1)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

func worker(domainChan <-chan string, resultChan chan<- DomainInfo, wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range domainChan {
		domain = sanitizeDomain(domain)
		ip := lookupIP(domain)
		if ip == "" {
			continue
		}
		hostname := lookupHostname(ip)
		abuseContact := lookupAbuseContact(ip, hostname)

		resultChan <- DomainInfo{
			Domain:       domain,
			IP:           ip,
			Hostname:     hostname,
			AbuseContact: abuseContact,
		}
	}
}

func printData(data []DomainInfo, format string) {
	switch format {
	case "csv":
		printAsCSV(data)
	case "yaml":
		printAsYAML(data)
	case "json":
		printAsJSON(data)
	default:
		die("Invalid output format", ExitArgsError, "", fmt.Errorf("invalid output format: %s", format))
	}
}

func printAsCSV(data []DomainInfo) {
	writer := csv.NewWriter(os.Stdout)
	writer.Comma = '\t'
	if err := writer.Write([]string{"Domain", "IP", "Hostname", "Abuse Contact"}); err != nil {
		die("Printing headers failed", ExitCSVError, "", err)
	}
	for _, info := range data {
		if err := writer.Write([]string{info.Domain, info.IP, info.Hostname, info.AbuseContact}); err != nil {
			die("Printing rows failed", ExitCSVError, "", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		die("Printing failed", ExitCSVError, "", err)
	}
}

func printAsYAML(data []DomainInfo) {
	yamlData, err := yaml.Marshal(data)
	if err != nil {
		die("YAML encoding failed", ExitCSVError, "", err)
	}
	fmt.Println(string(yamlData))
}

func printAsJSON(data []DomainInfo) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		die("JSON encoding failed", ExitCSVError, "", err)
	}
	fmt.Println(string(jsonData))
}

func loadListFile(file string, defaultList []string) []string {
	if file == "" {
		return defaultList
	}
	serversFile, err := os.Open(file)
	if err != nil {
		fmt.Printf("Error opening %s: %v\n", file, err)
		return defaultList
	}
	defer serversFile.Close()

	var servers []string
	scanner := bufio.NewScanner(serversFile)
	for scanner.Scan() {
		server := scanner.Text()
		if server != "" {
			servers = append(servers, server)
		}
	}

	if len(servers) == 0 {
		return defaultList
	}
	return servers
}

func loadContacts(file string) {
	var contacts map[string]string
	_ = yaml.Unmarshal([]byte(strContacts), &contacts) // attempt to load the embedded contacts as default

	if file == "" {
		abuseContacts = contacts
		return
	}
	contactsFile, err := os.Open(file)
	if err != nil {
		abuseContacts = contacts
		return
	}
	defer contactsFile.Close()

	decoder := yaml.NewDecoder(contactsFile)
	if err := decoder.Decode(&contacts); err != nil {
		die("Error decoding abuse contacts file", ExitFileError, "", err)
	}
	abuseContacts = contacts
	return
}

func loadDomains(file string) {
	domains = append(loadListFile(file, []string{}), flag.Args()...) // append domains given as CLI args
	if fileInfo, _ := os.Stdin.Stat(); (fileInfo.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			domain := scanner.Text()
			if domain != "" {
				domains = append(domains, domain)
			}
		}
		_ = scanner.Err() // we ignore scanner errors because domains might have been loaded in a different way
	}
}

func loadDNSServers(file string) {
	dnsServers = loadListFile(file, strings.Split(strings.TrimSpace(strDNS), "\n"))
}

func gatherData(numWorkers int) []DomainInfo {
	domainChan := make(chan string, len(domains))
	resultChan := make(chan DomainInfo, len(domains))

	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(domainChan, resultChan, &wg)
	}

	for _, domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []DomainInfo
	for info := range resultChan {
		results = append(results, info)
	}
	return results
}

func main() {
	dnsFile := flag.String("dns", "", "File with list of DNS servers")
	domainsFile := flag.String("d", "", "File with list of domain names")
	outputFormat := flag.String("o", "csv", "Output format (csv, yaml, json)")
	workerCount := flag.Int("w", 5, "Number of worker goroutines")
	contactsFile := flag.String("c", "", "File with list of known abuse contacts (YAML format, 'domain: contact')")
	flag.Parse()

	loadContacts(*contactsFile)
	loadDomains(*domainsFile)
	loadDNSServers(*dnsFile)
	data := gatherData(*workerCount)
	printData(data, *outputFormat)
}
