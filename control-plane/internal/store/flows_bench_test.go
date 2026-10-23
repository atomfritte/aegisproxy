package store

import (
	"fmt"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// BenchmarkRecordFlowBatch measures flow ingestion (what every data-plane request costs the control-plane).
func BenchmarkRecordFlowBatch(b *testing.B) {
	st := newTestStore(b, b.TempDir(), false)
	batch := make([]models.TrafficFlow, 50)
	for i := range batch {
		batch[i] = models.TrafficFlow{ServerIP: "10.1.0.5", Method: "GET", Scheme: "https", Host: "pkgs.example.org",
			Path: fmt.Sprintf("/simple/pkg-%d/", i), FullURL: fmt.Sprintf("https://pkgs.example.org/simple/pkg-%d/", i),
			UserAgent: "pip/24.0", Verdict: models.VerdictAllowed, StatusCode: 200, LatencyMs: 12, BytesReceived: 4096, Timestamp: time.Now()}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.RecordFlowBatch(batch)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(batch)), "ns/flow")
}
