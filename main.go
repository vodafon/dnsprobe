package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/vodafon/swork"
)

var (
	flagProcs          = flag.Int("procs", 20, "concurrency")
	flagTimeout        = flag.Duration("timeout", time.Second, "timeout for port scan")
	flagSkipCname      = flag.Bool("skip-cname", false, "skip CNAME records")
	flagCheckWildcard  = flag.Bool("check-wildcard", false, "skip wilecard records")
	flagVerbose        = flag.Bool("v", false, "verbose")
	flagShowUnresolved = flag.Bool("unresolved", false, "show only unresolved domains")
	flagServer         = flag.String("server", "8.8.8.8:53", "dns server")
)

type DNSProbe struct {
	*sync.Mutex
	server         string
	random         string
	wildcards      map[string][]string
	showUnresolved bool
}

func (obj *DNSProbe) Process(url string) {
	domain := strings.ToLower(url)
	for _, prefix := range []string{"http://", "https://"} {
		domain = strings.TrimPrefix(domain, prefix)
	}
	isResolved := obj.isValid(domain)
	if obj.showUnresolved && !isResolved {
		fmt.Println(url)
		return
	}
	if isResolved {
		fmt.Println(url)
		return
	}
}

func main() {
	flag.Parse()
	if *flagProcs < 1 || *flagServer == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	dnsProbe := &DNSProbe{
		Mutex:          &sync.Mutex{},
		server:         *flagServer,
		showUnresolved: *flagShowUnresolved,
		random:         randString(10),
		wildcards:      make(map[string][]string),
	}
	w := swork.NewWorkerGroup(*flagProcs, dnsProbe)

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		w.StringC <- sc.Text()
	}

	close(w.StringC)

	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
	}

	w.Wait()
}

func (obj *DNSProbe) checkIsValidWildcard(url string) bool {
	anss, err := obj.answers(url)
	if err != nil || len(anss) == 0 {
		return false
	}
	parts := strings.Split(url, ".")
	if len(parts) < 3 {
		return true
	}
	parent := obj.random + "." + strings.Join(parts[1:], ".")
	obj.Lock()
	answers, ok := obj.wildcards[parent]
	if !ok {
		answers = obj.parentAnswers(parent)
		obj.wildcards[parent] = answers
	}
	obj.Unlock()
	valid := !isIncludeSlices(anss, answers)
	if valid && *flagVerbose {
		log.Printf("%s: %s", url, anss)
	}
	return valid
}

func isIncludeSlices(s1, s2 []string) bool {
	for _, el := range s1 {
		if !isInclude(el, s2) {
			return false
		}
	}
	return true
}

func isInclude(el string, list []string) bool {
	for _, li := range list {
		if el == li {
			return true
		}
	}
	return false
}

func (obj *DNSProbe) parentAnswers(parent string) []string {
	anss, err := obj.answers(parent)
	if err != nil {
		return []string{}
	}
	return anss
}

func (obj *DNSProbe) answers(url string) ([]string, error) {
	c := dns.Client{Timeout: *flagTimeout}
	m := dns.Msg{}
	m.SetQuestion(url+".", dns.TypeA)
	r, _, err := c.Exchange(&m, obj.server)
	if err != nil {
		return nil, err
	}
	res := []string{}
	for _, ans := range r.Answer {
		if t, ok := ans.(*dns.A); ok {
			res = append(res, t.A.String())
			continue
		}
		if t, ok := ans.(*dns.CNAME); ok {
			if *flagSkipCname {
				return []string{}, nil
			}
			res = append(res, t.Target)
		}
	}
	return res, nil
}

func (obj *DNSProbe) isValid(url string) bool {
	if *flagCheckWildcard {
		return obj.checkIsValidWildcard(url)
	}
	anss, err := obj.answers(url)
	if err != nil || len(anss) == 0 {
		return false
	}
	if *flagVerbose {
		log.Printf("%s: %s", url, anss)
	}
	return true
}

func randString(l int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")
	var b strings.Builder
	for i := 0; i < l; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}
