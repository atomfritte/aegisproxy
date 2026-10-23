package store

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// EstimateFlowBytes synthesizes plausible transfer sizes for demo traffic (AEGIS_DEMO_MODE only).
func EstimateFlowBytes(flow models.TrafficFlow) (int64, int64) {
	if flow.BytesReceived > 0 || flow.BytesSent > 0 {
		sent := flow.BytesSent
		if sent == 0 {
			sent = 1420
		}
		return sent, flow.BytesReceived
	}
	if flow.Verdict == "BLOCKED" {
		return 840, 2150
	}
	u := strings.ToLower(flow.FullURL)
	switch {
	case strings.Contains(u, ".whl") || strings.Contains(u, "onnxruntime") || strings.Contains(u, "blobs/sha256"):
		return 2400, 148_500_000 // ~148.5 MB
	case strings.Contains(u, ".tar.gz") || strings.Contains(u, ".tgz") || strings.Contains(u, ".deb") || strings.Contains(u, ".zip"):
		return 1850, 42_300_000 // ~42.3 MB
	case strings.Contains(u, "windowsupdate.com"):
		return 3100, 64_800_000 // ~64.8 MB
	case strings.Contains(u, "ubuntu.com") || strings.Contains(u, "pkgs.k8s.io"):
		return 1200, 8_400_000 // ~8.4 MB
	default:
		return 1450, 1_850_000 // ~1.85 MB
	}
}

// trafficAggregator keeps rolling 24h telemetry: per-minute throughput buckets plus hourly
// per-server and per-destination volume tables (bounded cardinality).
type trafficAggregator struct {
	mu      sync.Mutex
	minutes [24 * 60]minuteBucket
	hours   [24]hourBucket
}

type minuteBucket struct {
	minute                     int64
	direct, cdn, bypass, total int64
	requests                   int64
}

type volAgg struct {
	hostname, ip   string
	groups         []string
	sent, received int64
	requests       int64
	topDest        map[string]int64
	path           string
	ruleName       string
	tlsIntercepted bool
	redirectAsset  bool
	category       string
}

type hourBucket struct {
	hour    int64
	servers map[string]*volAgg
	dests   map[string]*volAgg
}

const maxAggKeysPerHour = 5000

func newTrafficAggregator() *trafficAggregator { return &trafficAggregator{} }

func destCategory(f models.TrafficFlow) string {
	switch f.Verdict {
	case models.VerdictTLSBypass:
		return "SSL/TLS No-Break Passthrough"
	case models.VerdictRedirectObject:
		return "302 Redirect Objects (CDN)"
	case models.VerdictLearningAllowed:
		return "Learning Session Capture"
	case models.VerdictAllowed:
		return "Whitelisted Destination"
	}
	return "Blocked Attempts"
}

func (t *trafficAggregator) add(f models.TrafficFlow) {
	ts := f.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	if time.Since(ts) > 24*time.Hour {
		return
	}
	bytes := f.BytesSent + f.BytesReceived
	minute := ts.Unix() / 60
	hour := ts.Unix() / 3600

	t.mu.Lock()
	defer t.mu.Unlock()
	mb := &t.minutes[minute%int64(len(t.minutes))]
	if mb.minute != minute {
		*mb = minuteBucket{minute: minute}
	}
	mb.requests++
	if models.IsAllowedVerdict(f.Verdict) {
		mb.total += bytes
		switch f.Verdict {
		case models.VerdictRedirectObject:
			mb.cdn += bytes
		case models.VerdictTLSBypass:
			mb.bypass += bytes
		default:
			mb.direct += bytes
		}
	}

	hb := &t.hours[hour%24]
	if hb.hour != hour || hb.servers == nil {
		*hb = hourBucket{hour: hour, servers: map[string]*volAgg{}, dests: map[string]*volAgg{}}
	}
	if sv := hb.servers[f.ServerID]; sv != nil || len(hb.servers) < maxAggKeysPerHour {
		if sv == nil {
			sv = &volAgg{hostname: f.ServerHostname, ip: f.ServerIP, groups: f.GroupIDs, topDest: map[string]int64{}}
			hb.servers[f.ServerID] = sv
		}
		sv.sent += f.BytesSent
		sv.received += f.BytesReceived
		sv.requests++
		if len(sv.topDest) < 64 || sv.topDest[f.Host] > 0 {
			sv.topDest[f.Host] += bytes + 1
		}
	}
	if models.IsAllowedVerdict(f.Verdict) {
		if dv := hb.dests[f.Host]; dv != nil || len(hb.dests) < maxAggKeysPerHour {
			if dv == nil {
				seg := strings.SplitN(strings.Trim(f.Path, "/"), "/", 2)[0]
				p := "/**"
				if seg != "" {
					p = "/" + seg + "/**"
				}
				dv = &volAgg{path: p, category: destCategory(f), tlsIntercepted: f.TLSIntercepted, redirectAsset: f.Verdict == models.VerdictRedirectObject}
				hb.dests[f.Host] = dv
			}
			dv.received += bytes
			dv.requests++
			if f.MatchedRuleName != "" {
				dv.ruleName = f.MatchedRuleName
			}
		}
	}
}

func (s *Store) ComputeBandwidthSummary() models.BandwidthSummary {
	s.bwMu.Lock()
	defer s.bwMu.Unlock()
	if s.bwCache != nil && time.Since(s.bwCachedAt) < 2*time.Second {
		return *s.bwCache
	}
	s.mu.RLock()
	groups := append([]models.ServerGroup(nil), s.state.Groups...)
	s.mu.RUnlock()

	summary := s.traffic.summarize(time.Now(), groups)
	if s.opts.DemoMode {
		summary = mergeDemoBaseline(summary, groups)
	}
	s.bwCache = &summary
	s.bwCachedAt = time.Now()
	return summary
}

func mbps(bytes int64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	v := float64(bytes) * 8 / seconds / 1e6
	return float64(int64(v*100)) / 100
}

func (t *trafficAggregator) summarize(now time.Time, groups []models.ServerGroup) models.BandwidthSummary {
	t.mu.Lock()
	defer t.mu.Unlock()
	nowMin := now.Unix() / 60
	nowHour := now.Unix() / 3600

	var total, cdn, bypass int64
	var peak float64
	window := func(endMin int64, span int64) (minuteBucket, bool) {
		var agg minuteBucket
		for m := endMin - span + 1; m <= endMin; m++ {
			b := t.minutes[((m%int64(len(t.minutes)))+int64(len(t.minutes)))%int64(len(t.minutes))]
			if b.minute != m {
				continue
			}
			agg.total += b.total
			agg.direct += b.direct
			agg.cdn += b.cdn
			agg.bypass += b.bypass
			agg.requests += b.requests
		}
		return agg, true
	}
	for w := int64(0); w < 96; w++ { // 24h in 15-minute windows
		agg, _ := window(nowMin-w*15, 15)
		total += agg.total
		cdn += agg.cdn
		bypass += agg.bypass
		if v := mbps(agg.total, 900); v > peak {
			peak = v
		}
	}
	series := make([]models.BandwidthSample, 0, 16)
	for i := 15; i >= 0; i-- {
		end := nowMin - int64(i)*15
		agg, _ := window(end, 15)
		ts := time.Unix(end*60, 0)
		series = append(series, models.BandwidthSample{
			TimeLabel:       fmt.Sprintf("%02d:%02d", ts.Hour(), ts.Minute()),
			MbpsTotal:       mbps(agg.total, 900),
			MbpsDirectAllow: mbps(agg.direct, 900),
			MbpsCDNObjects:  mbps(agg.cdn, 900),
			MbpsTLSBypass:   mbps(agg.bypass, 900),
			RequestsPerSec:  int(agg.requests / 900),
		})
	}
	cur, _ := window(nowMin, 5)

	servers := map[string]*models.ServerVolumeEntry{}
	serverDest := map[string]map[string]int64{}
	serverPeak := map[string]int64{}
	dests := map[string]*models.DestinationVolumeEntry{}
	for _, hb := range t.hours {
		if hb.servers == nil || nowHour-hb.hour >= 24 || hb.hour > nowHour {
			continue
		}
		for id, v := range hb.servers {
			e := servers[id]
			if e == nil {
				e = &models.ServerVolumeEntry{ServerID: id, Hostname: v.hostname, IP: v.ip, GroupIDs: v.groups}
				servers[id] = e
				serverDest[id] = map[string]int64{}
			}
			e.BytesSent += v.sent
			e.BytesReceived += v.received
			e.RequestCount += v.requests
			if hourBytes := v.sent + v.received; hourBytes > serverPeak[id] {
				serverPeak[id] = hourBytes
			}
			for h, b := range v.topDest {
				serverDest[id][h] += b
			}
		}
		for host, v := range hb.dests {
			e := dests[host]
			if e == nil {
				e = &models.DestinationVolumeEntry{Host: host, PathPattern: v.path, Category: v.category,
					TLSIntercepted: v.tlsIntercepted, IsRedirectAsset: v.redirectAsset}
				dests[host] = e
			}
			e.TotalBytes += v.received
			e.RequestCount += v.requests
			if v.ruleName != "" {
				e.ParentRuleName = v.ruleName
			}
		}
	}

	topServers := make([]models.ServerVolumeEntry, 0, len(servers))
	for id, e := range servers {
		e.TotalBytes = e.BytesSent + e.BytesReceived
		e.PeakMbps = mbps(serverPeak[id], 3600)
		var best string
		var bestB int64
		for h, b := range serverDest[id] {
			if b > bestB {
				best, bestB = h, b
			}
		}
		e.TopDestination = best
		topServers = append(topServers, *e)
	}
	sort.Slice(topServers, func(i, j int) bool { return topServers[i].TotalBytes > topServers[j].TotalBytes })
	if len(topServers) > 25 {
		topServers = topServers[:25]
	}
	topDests := make([]models.DestinationVolumeEntry, 0, len(dests))
	for _, e := range dests {
		topDests = append(topDests, *e)
	}
	sort.Slice(topDests, func(i, j int) bool { return topDests[i].TotalBytes > topDests[j].TotalBytes })
	if len(topDests) > 25 {
		topDests = topDests[:25]
	}

	return models.BandwidthSummary{
		CurrentMbps:         mbps(cur.total, 300),
		PeakMbps24h:         peak,
		TotalBytes24h:       total,
		CDNRedirectBytes24h: cdn,
		TLSBypassBytes24h:   bypass,
		TimeSeries:          series,
		TopServers:          topServers,
		TopDestinations:     topDests,
		GroupBreakdown:      groupBreakdown(groups, topServers),
	}
}

func groupBreakdown(groups []models.ServerGroup, servers []models.ServerVolumeEntry) []models.GroupVolumeEntry {
	groupMap := make(map[string]*models.GroupVolumeEntry, len(groups))
	for _, g := range groups {
		groupMap[g.ID] = &models.GroupVolumeEntry{GroupID: g.ID, GroupName: g.Name, ServerCount: g.ServerCount, Color: g.Color}
	}
	for _, srv := range servers {
		for _, gid := range srv.GroupIDs {
			if ge, ok := groupMap[gid]; ok {
				ge.TotalBytes += srv.TotalBytes
				ge.RequestCount += srv.RequestCount
				ge.CurrentMbps += srv.PeakMbps * 0.48
			}
		}
	}
	out := make([]models.GroupVolumeEntry, 0, len(groupMap))
	for _, ge := range groupMap {
		out = append(out, *ge)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TotalBytes > out[j].TotalBytes })
	return out
}

// mergeDemoBaseline overlays the static showcase volumes used by AEGIS_DEMO_MODE.
func mergeDemoBaseline(live models.BandwidthSummary, groups []models.ServerGroup) models.BandwidthSummary {
	serverMap := map[string]*models.ServerVolumeEntry{
		"srv-gpu-node-04": {
			ServerID:       "srv-gpu-node-04",
			Hostname:       "gpu-h100-node04.internal.corp",
			IP:             "10.50.2.14",
			GroupIDs:       []string{"grp-ai-gpu"},
			BytesReceived:  44_820_000_000, // 44.82 GB
			BytesSent:      610_000_000,
			RequestCount:   1840,
			PeakMbps:       840.5,
			TopDestination: "cdn-lfs.huggingface.co / download.pytorch.org",
		},
		"srv-k8s-worker-104": {
			ServerID:       "srv-k8s-worker-104",
			Hostname:       "k8s-prod-worker-104.internal.corp",
			IP:             "10.10.4.104",
			GroupIDs:       []string{"grp-k8s-prod"},
			BytesReceived:  28_450_000_000, // 28.45 GB
			BytesSent:      1_120_000_000,
			RequestCount:   12490,
			PeakMbps:       620.0,
			TopDestination: "registry-1.docker.io (/v2/library/**)",
		},
		"srv-ci-runner-02": {
			ServerID:       "srv-ci-runner-02",
			Hostname:       "ci-runner-fra02.internal.corp",
			IP:             "10.20.1.15",
			GroupIDs:       []string{"grp-ci-runners"},
			BytesReceived:  19_640_000_000, // 19.64 GB
			BytesSent:      2_340_000_000,
			RequestCount:   9320,
			PeakMbps:       510.2,
			TopDestination: "github.com/microsoft/** + objects.githubusercontent.com",
		},
		"srv-win-erp-09": {
			ServerID:       "srv-win-erp-09",
			Hostname:       "win-sap-conn-09.internal.corp",
			IP:             "10.40.8.19",
			GroupIDs:       []string{"grp-windows-srv"},
			BytesReceived:  14_210_000_000, // 14.21 GB
			BytesSent:      480_000_000,
			RequestCount:   4120,
			PeakMbps:       310.8,
			TopDestination: "*.windowsupdate.com (SSL No-Break Passthrough)",
		},
		"srv-linux-app-312": {
			ServerID:       "srv-linux-app-312",
			Hostname:       "rhel-billing-app-312.internal.corp",
			IP:             "10.30.12.55",
			GroupIDs:       []string{"grp-linux-core"},
			BytesReceived:  9_850_000_000, // 9.85 GB
			BytesSent:      310_000_000,
			RequestCount:   15800,
			PeakMbps:       245.0,
			TopDestination: "security.ubuntu.com (/ubuntu/**)",
		},
		"srv-ci-runner-01": {
			ServerID:       "srv-ci-runner-01",
			Hostname:       "ci-runner-fra01.internal.corp",
			IP:             "127.0.0.1",
			GroupIDs:       []string{"grp-ci-runners"},
			BytesReceived:  6_420_000_000, // 6.42 GB
			BytesSent:      890_000_000,
			RequestCount:   5410,
			PeakMbps:       295.4,
			TopDestination: "github.com/microsoft/** (Release Artifacts)",
		},
		"srv-db-vault-01": {
			ServerID:       "srv-db-vault-01",
			Hostname:       "vault-core-01.internal.corp",
			IP:             "10.60.1.10",
			GroupIDs:       []string{"grp-db-vault"},
			BytesReceived:  420_000_000, // 420 MB (mTLS replication only)
			BytesSent:      410_000_000,
			RequestCount:   980,
			PeakMbps:       45.0,
			TopDestination: "vault-dr.enterprise.corp (mTLS Passthrough)",
		},
	}

	destMap := map[string]*models.DestinationVolumeEntry{
		"huggingface.co": {
			Host:            "cdn-lfs.huggingface.co & huggingface.co",
			PathPattern:     "/meta-llama/**",
			Category:        "AI Model Weights (302 LFS Objects)",
			TotalBytes:      38_900_000_000, // 38.9 GB
			RequestCount:    4190,
			TLSIntercepted:  true,
			IsRedirectAsset: true,
			ParentRuleName:  "HuggingFace: Meta-Llama Weights & LFS Objects",
		},
		"registry-1.docker.io": {
			Host:            "registry-1.docker.io & cloudflare.docker.com",
			PathPattern:     "/v2/library/**",
			Category:        "Container Image Layers (302 Blob Redirects)",
			TotalBytes:      29_150_000_000, // 29.15 GB
			RequestCount:    32150,
			TLSIntercepted:  true,
			IsRedirectAsset: true,
			ParentRuleName:  "Docker Hub: Official Library Images (/v2/library/**)",
		},
		"github.com/microsoft": {
			Host:            "github.com & objects.githubusercontent.com",
			PathPattern:     "/microsoft/**",
			Category:        "GitHub Microsoft Releases & Codeload Tarballs",
			TotalBytes:      24_780_000_000, // 24.78 GB
			RequestCount:    14820,
			TLSIntercepted:  true,
			IsRedirectAsset: true,
			ParentRuleName:  "GitHub: Microsoft Org & Release Objects Only",
		},
		"windowsupdate.com": {
			Host:            "*.windowsupdate.com",
			PathPattern:     "/**",
			Category:        "OS Updates (SSL/TLS No-Break Passthrough)",
			TotalBytes:      14_690_000_000, // 14.69 GB
			RequestCount:    4120,
			TLSIntercepted:  false,
			IsRedirectAsset: false,
			ParentRuleName:  "TLS Passthrough: *.windowsupdate.com",
		},
		"ubuntu.com": {
			Host:            "security.ubuntu.com & archive.ubuntu.com",
			PathPattern:     "/ubuntu/**",
			Category:        "Linux APT Security Packages (.deb)",
			TotalBytes:      12_340_000_000, // 12.34 GB
			RequestCount:    89410,
			TLSIntercepted:  true,
			IsRedirectAsset: false,
			ParentRuleName:  "Ubuntu & Debian Official APT Security Mirrors",
		},
		"pytorch.org": {
			Host:            "download.pytorch.org & files.pythonhosted.org",
			PathPattern:     "/whl/cu124/**",
			Category:        "CUDA / Python Wheel Artifacts",
			TotalBytes:      8_640_000_000, // 8.64 GB
			RequestCount:    2310,
			TLSIntercepted:  true,
			IsRedirectAsset: false,
			ParentRuleName:  "Learning Session: PyTorch 2.4 Setup",
		},
	}

	for _, e := range live.TopServers {
		if b, ok := serverMap[e.ServerID]; ok {
			b.BytesSent += e.BytesSent
			b.BytesReceived += e.BytesReceived
			b.RequestCount += e.RequestCount
		} else {
			cp := e
			serverMap[e.ServerID] = &cp
		}
	}
	for _, e := range live.TopDestinations {
		if _, ok := destMap[e.Host]; !ok {
			cp := e
			destMap[e.Host] = &cp
		}
	}
	topServers := make([]models.ServerVolumeEntry, 0, len(serverMap))
	for _, v := range serverMap {
		v.TotalBytes = v.BytesReceived + v.BytesSent
		topServers = append(topServers, *v)
	}
	sort.Slice(topServers, func(i, j int) bool { return topServers[i].TotalBytes > topServers[j].TotalBytes })
	topDests := make([]models.DestinationVolumeEntry, 0, len(destMap))
	var totalBytes, cdnBytes, bypassBytes int64
	for _, d := range destMap {
		totalBytes += d.TotalBytes
		if d.IsRedirectAsset {
			cdnBytes += d.TotalBytes
		}
		if !d.TLSIntercepted {
			bypassBytes += d.TotalBytes
		}
		topDests = append(topDests, *d)
	}
	sort.Slice(topDests, func(i, j int) bool { return topDests[i].TotalBytes > topDests[j].TotalBytes })

	now := time.Now()
	baseDirect := []float64{380, 410, 445, 520, 490, 530, 610, 580, 640, 690, 660, 710, 740, 695, 730, 765}
	baseCDN := []float64{420, 460, 510, 680, 640, 710, 820, 790, 860, 940, 890, 980, 1040, 960, 1010, 1085}
	baseBypass := []float64{110, 115, 130, 145, 140, 155, 170, 165, 180, 195, 185, 210, 225, 200, 215, 230}
	series := make([]models.BandwidthSample, 0, len(baseDirect))
	var peak float64
	for i := range baseDirect {
		t := now.Add(time.Duration(-(len(baseDirect)-1-i)*15) * time.Minute)
		var lv models.BandwidthSample
		if i < len(live.TimeSeries) {
			lv = live.TimeSeries[i]
		}
		dir, cdn, byp := baseDirect[i]+lv.MbpsDirectAllow, baseCDN[i]+lv.MbpsCDNObjects, baseBypass[i]+lv.MbpsTLSBypass
		tot := dir + cdn + byp
		peak = max(peak, tot)
		series = append(series, models.BandwidthSample{
			TimeLabel: fmt.Sprintf("%02d:%02d", t.Hour(), t.Minute()), MbpsTotal: tot,
			MbpsDirectAllow: dir, MbpsCDNObjects: cdn, MbpsTLSBypass: byp, RequestsPerSec: int(tot * 1.8),
		})
	}
	return models.BandwidthSummary{
		CurrentMbps:         series[len(series)-1].MbpsTotal,
		PeakMbps24h:         peak,
		TotalBytes24h:       totalBytes + live.TotalBytes24h,
		CDNRedirectBytes24h: cdnBytes + live.CDNRedirectBytes24h,
		TLSBypassBytes24h:   bypassBytes + live.TLSBypassBytes24h,
		TimeSeries:          series,
		TopServers:          topServers,
		TopDestinations:     topDests,
		GroupBreakdown:      groupBreakdown(groups, topServers),
	}
}
