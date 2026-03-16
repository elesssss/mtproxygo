package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// ── 获取公网 IP ───────────────────────────────────────────────────────────────

func dbgf(cfg *Config, format string, args ...interface{}) {
	if cfg != nil && cfg.Debug {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

func getIPFromURL(url string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func initIPInfo(cfg *Config) {
	ipv4 := getIPFromURL("http://v4.ident.me/")
	if ipv4 == "" {
		ipv4 = getIPFromURL("http://ipv4.icanhazip.com/")
	}
	ipv6 := getIPFromURL("http://v6.ident.me/")
	if ipv6 == "" {
		ipv6 = getIPFromURL("http://ipv6.icanhazip.com/")
	}
	if ipv6 != "" && !strings.Contains(ipv6, ":") {
		ipv6 = ""
	}
	myIPInfo.Set(ipv4, ipv6)

	if ipv6 != "" && (cfg.PreferIPv6 || ipv4 == "") {
		fmt.Fprintln(os.Stderr, "IPv6 found, using it for external communication")
	}
	if cfg.UseMiddleProxy && ipv4 == "" && ipv6 == "" {
		fmt.Fprintln(os.Stderr, "Failed to determine your ip, advertising disabled")
		disableMiddleProxy = true
	}
}

// ── 打印代理链接 ──────────────────────────────────────────────────────────────

var currentProxyLinks []map[string]string

func printTGInfo(cfg *Config) []map[string]string {
	ipv4, ipv6 := myIPInfo.Get()
	var ipAddrs []string

	if cfg.MyDomain != "" {
		ipAddrs = []string{cfg.MyDomain}
	} else {
		if ipv4 != "" {
			ipAddrs = append(ipAddrs, ipv4)
		}
		if ipv6 != "" {
			ipAddrs = append(ipAddrs, ipv6)
		}
		if len(ipAddrs) == 0 {
			fmt.Fprintln(os.Stderr, "Warning: could not determine public IP")
			return nil
		}
	}

	defaultSecrets := map[string]bool{
		"00000000000000000000000000000000": true,
		"0123456789abcdef0123456789abcdef": true,
		"00000000000000000000000000000001": true,
	}

	var links []map[string]string
	printDefault := false

	for _, secret := range cfg.Secrets {
		secretHex := hex.EncodeToString(secret)
		for _, ip := range ipAddrs {
			if cfg.Modes.Classic {
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s",
					ip, cfg.Port, secretHex)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				fmt.Printf("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
			if cfg.Modes.Secure {
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=dd%s",
					ip, cfg.Port, secretHex)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				fmt.Printf("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
			if cfg.Modes.TLS {
				tlsSecret := "ee" + secretHex + hex.EncodeToString([]byte(cfg.TLSDomain))
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s",
					ip, cfg.Port, tlsSecret)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				fmt.Printf("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
		}

		if defaultSecrets[secretHex] {
			fmt.Printf("The default secret %s is used, this is not recommended\n", secretHex)
			rnd := globalRand.Bytes(16)
			fmt.Printf("You can change it to this random secret: %s\n", hex.EncodeToString(rnd))
			printDefault = true
		}
	}

	if cfg.TLSDomain == "www.google.com" {
		fmt.Println("The default TLS_DOMAIN www.google.com is used, this is not recommended")
		printDefault = true
	}
	if printDefault {
		fmt.Fprintln(os.Stderr, "Warning: one or more default settings detected")
	}

	return links
}

// ── 服务器启动 ────────────────────────────────────────────────────────────────

func startServers(cfg *Config) []io.Closer {
	var listeners []io.Closer

	if cfg.ListenAddrIPv4 != "" {
		addr := fmt.Sprintf("%s:%d", cfg.ListenAddrIPv4, cfg.Port)
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to listen on %s: %v\n", addr, err)
		} else {
			fmt.Fprintf(os.Stderr, "Listening on %s\n", addr)
			listeners = append(listeners, ln)
			go acceptLoop(ln, cfg)
		}
	}

	if cfg.ListenAddrIPv6 != "" {
		addr := fmt.Sprintf("[%s]:%d", cfg.ListenAddrIPv6, cfg.Port)
		ln, err := net.Listen("tcp6", addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to listen on %s: %v\n", addr, err)
		} else {
			fmt.Fprintf(os.Stderr, "Listening on %s\n", addr)
			listeners = append(listeners, ln)
			go acceptLoop(ln, cfg)
		}
	}

	if cfg.ListenUnixSock != "" {
		os.Remove(cfg.ListenUnixSock)
		ln, err := net.Listen("unix", cfg.ListenUnixSock)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to listen on unix %s: %v\n", cfg.ListenUnixSock, err)
		} else {
			listeners = append(listeners, ln)
			go acceptLoop(ln, cfg)
		}
	}

	return listeners
}

func acceptLoop(ln net.Listener, cfg *Config) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleClientWrapper(conn, cfg)
	}
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	configPath := parseArgs()

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置加载失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化全局状态
	usedHandshakes = newReplayCache(cfg.ReplayCheckLen)
	clientIPs = newReplayCache(cfg.ClientIPsLen)

	initIPInfo(cfg)
	currentProxyLinks = printTGInfo(cfg)

	// 后台任务
	go statsPrinter(cfg)
	go getMaskHostCertLen(cfg)
	go clearIPResolvingCache()

	if cfg.UseMiddleProxy {
		go updateMiddleProxyInfo(cfg)
		if cfg.GetTimePeriod > 0 {
			go getSrvTime(cfg)
		}
	}

	// metrics server
	startMetricsServer(cfg, currentProxyLinks)

	// 启动代理服务器
	listeners := startServers(cfg)
	if len(listeners) == 0 {
		fmt.Fprintln(os.Stderr, "没有可用的监听地址，退出")
		os.Exit(1)
	}

	// SIGUSR2 热重载
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGUSR2)
	go func() {
		for range reloadCh {
			newCfg, err := loadConfig(configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "配置重载失败: %v\n", err)
				continue
			}
			*cfg = *newCfg
			usedHandshakes = newReplayCache(cfg.ReplayCheckLen)
			currentProxyLinks = printTGInfo(cfg)
			fmt.Fprintln(os.Stderr, "Config reloaded")
		}
	}()

	// 等待退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Fprintln(os.Stderr, "Shutting down...")
	for _, ln := range listeners {
		ln.Close()
	}
}