package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"golang.org/x/net/proxy"
)

const pacFileTemplate = `
function FindProxyForURL(url, host) {
	return "SOCKS5 %s; SOCKS %s; DIRECT";
}
`

var (
	dest          = flag.String("dest", "127.0.0.1:7070", "dest socks5 proxy addr")
	socks5listen  = flag.String("socks5_listen", "127.0.0.1:7071", "listen addr")
	pacListenAddr = flag.String("pac_listen", "127.0.0.1:7072", "pac listen addr")
	pacToAddr     = flag.String("pac_to", "127.0.0.1:7071", "pac proxy to addr")
	blockTime     = flag.Int("block_time", 600, "fail block time (seconds)")
	retryTime     = flag.Int("retry_time", 200, "retry proxy time (milliseconds)")
	skipLocalAddr = flag.Bool("skip_local_addr", true, "skip local addr")
	dns           = flag.String("dns", "1.1.1.1", "dns")
	resolver      = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if *dns != "" {
				address = *dns
			}
			if !strings.Contains(address, ":") {
				address += ":53"
			}
			return net.Dial(network, address)
		}}
	dialer         = &net.Dialer{Timeout: time.Second * 3, KeepAlive: time.Minute, Resolver: resolver}
	proxyDialer, _ = proxy.SOCKS5("tcp", *dest, nil, dialer)
	_, iplocal, _  = net.ParseCIDR("127.0.0.0/8")
	_, ip8, _      = net.ParseCIDR("10.0.0.0/8")
	_, ip12, _     = net.ParseCIDR("172.16.0.0/12")
	_, ip16, _     = net.ParseCIDR("192.168.0.0/16")
	proxyAddrs     sync.Map // map[addr]time.Time
)

type ConnErr struct {
	Direct bool
	Conn   net.Conn
	Err    error
}

// =====================================================================================

type RuleSet struct {
}

func (r *RuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	ctx = context.WithValue(ctx, "ts", strconv.FormatInt(time.Now().UnixNano(), 36))
	if req.DestAddr.FQDN != "" {
		ctx = context.WithValue(ctx, "domain", req.DestAddr.FQDN)
	}
	return ctx, true
}

// =====================================================================================

func str(direct bool) string {
	if direct {
		return "direct"
	}
	return "proxy"
}

func isPrivateIP(ip net.IP) bool {
	return iplocal.Contains(ip) || ip8.Contains(ip) || ip12.Contains(ip) || ip16.Contains(ip)
}

// =====================================================================================

type Conn struct {
	net.Conn
	logger *log.Logger
}

func (c *Conn) Close() error {
	err := c.Conn.Close()
	c.logger.Println("close conn", err)
	return err
}

// =====================================================================================

func dial(ctx context.Context, network string, address string) (conn net.Conn, err error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		log.Println("invalid address", address)
		return
	}
	ts, domain := ctx.Value("ts").(string), ctx.Value("domain")
	prefix := fmt.Sprintf("%-36s", ts+"\t"+address)
	logger := log.New(os.Stderr, prefix, log.Lshortfile|log.LstdFlags|log.Lmicroseconds)
	ip := net.ParseIP(host)
	if *skipLocalAddr && ip != nil && isPrivateIP(ip) {
		logger.Println("local addr, direct access")
		conn, err = dialer.DialContext(ctx, network, address)
		return &Conn{Conn: conn, logger: logger}, err
	}
	addrs := []string{host}
	if domain != nil {
		logger.Println("===>", domain)
		addrs = append(addrs, domain.(string))
	}
	if rand.Intn(10) > 0 {
		for _, addr := range addrs {
			if v, ok := proxyAddrs.Load(addr); ok &&
				time.Since(v.(time.Time)) < time.Duration(*blockTime)*time.Second {
				logger.Println("blocked address, use proxy", address, domain)
				conn, err = proxyDialer.Dial(network, address)
				return &Conn{Conn: conn, logger: logger}, err
			}
		}
	} else {
		logger.Println("rate try direct")
	}
	ch := make(chan ConnErr, 2)
	go func() {
		conn, err := dialer.DialContext(ctx, network, address)
		if e, ok := err.(net.Error); ok && (e.Timeout() || strings.Contains(err.Error(), "reset by peer")) {
			for _, addr := range addrs {
				proxyAddrs.Store(addr, time.Now())
			}
			logger.Println("store blocked address because", err)
		}
		ch <- ConnErr{true, conn, err}
	}()
	select {
	case ce := <-ch:
		if ce.Err != nil {
			logger.Println("use proxy because", str(ce.Direct), "failed", ce.Err)
			conn, err = proxyDialer.Dial(network, address)
			return &Conn{Conn: conn, logger: logger}, err
		}
		// success, remove from blocked list
		for _, addr := range addrs {
			proxyAddrs.Delete(addr)
		}
		logger.Println(str(ce.Direct), "connect success")
		return &Conn{Conn: ce.Conn, logger: logger}, ce.Err
	case <-time.After(time.Millisecond * time.Duration(rand.Intn(100)+*retryTime)):
		logger.Println("try to use proxy")
		go func() {
			if domain != nil && net.ParseIP(domain.(string)) == nil {
				result, _ := resolver.LookupHost(ctx, domain.(string))
				if len(result) != 0 {
					oldAddress := address
					if oldAddress != result[0] {
						address = fmt.Sprintf("%v:%v", result[0], port)
						logger.Printf("proxy resolve %v %v -> %v", domain, oldAddress, result[0])
					}
				}
			}
			conn, err := proxyDialer.Dial(network, address)
			ch <- ConnErr{false, conn, err}
		}()
	}
	var finishCount int
	defer func() {
		go func() {
			for ; finishCount < 2; finishCount++ {
				ce := <-ch
				if ce.Err == nil {
					logger.Println("close no use conn", str(ce.Direct), ce.Err, ce.Conn.Close())
					continue
				}
				logger.Println("failed conn", str(ce.Direct), ce.Err)
			}
		}()
	}()
	for i := 0; i < 2; i++ {
		ce := <-ch
		finishCount++
		if ce.Err != nil {
			log.Println(str(ce.Direct), "failed, wait ", str(!ce.Direct), ce.Err)
			continue
		}
		logger.Println(str(ce.Direct), "success")
		return &Conn{Conn: ce.Conn, logger: logger}, ce.Err
	}
	return nil, errors.New("dial failed")
}

func runPacServer() {
	pacData := []byte(fmt.Sprintf(pacFileTemplate, *pacToAddr, *pacToAddr))
	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		log.Println("get pac file from", req.RemoteAddr, req.Header.Get("User-Agent"))
		rw.Write(pacData)
	})
	log.Println("pac server listen", *pacListenAddr, "to", *pacToAddr)
	log.Panic(http.ListenAndServe(*pacListenAddr, nil))
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	go func() {
		for {
			time.Sleep(time.Second * 10)
			proxyAddrs.Range(func(key, value interface{}) bool {
				if time.Since(value.(time.Time)) > time.Minute*5 {
					proxyAddrs.Delete(key)
				}
				return true
			})
		}
	}()
}

type Resolver struct {
	nr *net.Resolver
}

func (r *Resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := r.nr.LookupHost(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	ip := net.ParseIP(addrs[0])
	return ctx, ip, err

}

func main() {
	flag.Parse()
	log.Println("use dns", *dns)
	go runPacServer()
	conf := &socks5.Config{}
	conf.Rules = &RuleSet{}
	conf.Dial = dial
	conf.Resolver = &Resolver{resolver}
	server, err := socks5.New(conf)
	if err != nil {
		log.Panic(err)
	}
	log.Println("socks5 server listen at", *socks5listen)
	log.Panic(server.ListenAndServe("tcp", *socks5listen))
}
