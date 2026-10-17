// SPDX-License-Identifier: BUSL-1.1
// loadgen is an open-loop, fixed-rate HTTP load generator for the Aegis gateway
// benchmark (v4 manual H5). It schedules requests at exact intervals so slow
// responses cannot hide latency (no coordinated omission) and prints JSON.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type result struct {
	Target     string         `json:"target"`
	Host       string         `json:"host"`
	Method     string         `json:"method"`
	BodyBytes  int            `json:"body_bytes"`
	RateRPS    int            `json:"target_rps"`
	Duration   string         `json:"duration"`
	Sent       int            `json:"requests_sent"`
	Statuses   map[string]int `json:"statuses"`
	Errors     int            `json:"transport_errors"`
	Achieved   float64        `json:"achieved_rps"`
	P50, P95   float64
	P99, Max   float64
	MeanMillis float64 `json:"mean_ms"`
}

func pct(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	i := int(float64(len(xs)-1) * p)
	return xs[i]
}

func main() {
	target := flag.String("url", "", "full URL including path and query")
	host := flag.String("host", "", "Host header")
	rate := flag.Int("rps", 100, "requests per second")
	dur := flag.Duration("duration", 30*time.Second, "test duration")
	body := flag.Int("body", 0, "POST body size in bytes (0 = GET)")
	warm := flag.Duration("warmup", 5*time.Second, "warm-up excluded from results")
	flag.Parse()
	if *target == "" || *rate < 1 || *rate > 5000 {
		fmt.Fprintln(os.Stderr, "usage: loadgen -url URL [-host H] [-rps N] [-duration D] [-body BYTES]")
		os.Exit(2)
	}
	payload := []byte(strings.Repeat("a", *body))
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 512, MaxConnsPerHost: 0, IdleConnTimeout: 30 * time.Second}}
	send := func() (float64, string, bool) {
		var req *http.Request
		if *body > 0 {
			req, _ = http.NewRequest("POST", *target, bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req, _ = http.NewRequest("GET", *target, nil)
		}
		if *host != "" {
			req.Host = *host
		}
		start := time.Now()
		resp, e := client.Do(req)
		if e != nil {
			return 0, "", false
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return float64(time.Since(start).Microseconds()) / 1000, fmt.Sprint(resp.StatusCode), true
	}
	run := func(d time.Duration, record bool) result {
		var mu sync.Mutex
		var wg sync.WaitGroup
		lat := []float64{}
		r := result{Target: *target, Host: *host, Method: map[bool]string{true: "POST", false: "GET"}[*body > 0], BodyBytes: *body, RateRPS: *rate, Duration: d.String(), Statuses: map[string]int{}}
		interval := time.Second / time.Duration(*rate)
		start := time.Now()
		for n := 0; ; n++ {
			at := start.Add(time.Duration(n) * interval)
			if at.Sub(start) >= d {
				break
			}
			time.Sleep(time.Until(at))
			wg.Add(1)
			go func() {
				defer wg.Done()
				ms, status, ok := send()
				mu.Lock()
				defer mu.Unlock()
				r.Sent++
				if !ok {
					r.Errors++
					return
				}
				r.Statuses[status]++
				lat = append(lat, ms)
			}()
		}
		wg.Wait()
		elapsed := time.Since(start).Seconds()
		sort.Float64s(lat)
		sum := 0.0
		for _, v := range lat {
			sum += v
		}
		if len(lat) > 0 {
			r.MeanMillis = sum / float64(len(lat))
			r.Max = lat[len(lat)-1]
		}
		r.P50, r.P95, r.P99 = pct(lat, .50), pct(lat, .95), pct(lat, .99)
		r.Achieved = float64(r.Sent) / elapsed
		return r
	}
	run(*warm, false)
	out := run(*dur, true)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"target": out.Target, "host": out.Host, "method": out.Method, "body_bytes": out.BodyBytes, "target_rps": out.RateRPS, "duration": out.Duration, "requests_sent": out.Sent, "statuses": out.Statuses, "transport_errors": out.Errors, "achieved_rps": out.Achieved, "p50_ms": out.P50, "p95_ms": out.P95, "p99_ms": out.P99, "max_ms": out.Max, "mean_ms": out.MeanMillis})
}
