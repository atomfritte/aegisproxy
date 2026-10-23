package api

import (
	"time"

	"aegisproxy/control-plane/internal/models"
)

// demoSessionFlows returns canned learning-session traffic for AEGIS_DEMO_MODE showcases.
func demoSessionFlows(sess models.LearningSession, scenario string) []models.TrafficFlow {
	now := time.Now().UTC()
	var sampleFlows []models.TrafficFlow
	switch scenario {
	case "docker_k8s_pull":
		sampleFlows = []models.TrafficFlow{
			{
				ServerIP: sess.ServerIP, ServerID: sess.ServerID, ServerHostname: sess.ServerHostname, GroupIDs: sess.GroupIDs,
				Method: "GET", Scheme: "https", Host: "nvcr.io", Path: "/v2/nvidia/cuda/manifests/12.4.1-base-ubuntu22.04",
				FullURL: "https://nvcr.io/v2/nvidia/cuda/manifests/12.4.1-base-ubuntu22.04", UserAgent: "containerd/1.7.22",
				Verdict: "LEARNING_ALLOWED", StatusCode: 307, RedirectLocation: "https://layers.nvcr.io/registry/docker/registry/v2/blobs/sha256/4b/4b9a81f/data",
				LatencyMs: 41, TLSIntercepted: true, SessionID: sess.ID, Timestamp: now,
			},
			{
				ServerIP: sess.ServerIP, ServerID: sess.ServerID, ServerHostname: sess.ServerHostname, GroupIDs: sess.GroupIDs,
				Method: "GET", Scheme: "https", Host: "layers.nvcr.io", Path: "/registry/docker/registry/v2/blobs/sha256/4b/4b9a81f/data",
				FullURL: "https://layers.nvcr.io/registry/docker/registry/v2/blobs/sha256/4b/4b9a81f/data", UserAgent: "containerd/1.7.22",
				Verdict: "LEARNING_ALLOWED", StatusCode: 200, RedirectParentURL: "https://nvcr.io/v2/nvidia/cuda/manifests/12.4.1-base-ubuntu22.04",
				LatencyMs: 215, TLSIntercepted: true, SessionID: sess.ID, Timestamp: now,
			},
			{
				ServerIP: sess.ServerIP, ServerID: sess.ServerID, ServerHostname: sess.ServerHostname, GroupIDs: sess.GroupIDs,
				Method: "GET", Scheme: "https", Host: "helm.ngc.nvidia.com", Path: "/nvidia/gpu-operator/index.yaml",
				FullURL: "https://helm.ngc.nvidia.com/nvidia/gpu-operator/index.yaml", UserAgent: "Helm/3.16",
				Verdict: "LEARNING_ALLOWED", StatusCode: 200, LatencyMs: 55, TLSIntercepted: true, SessionID: sess.ID, Timestamp: now,
			},
		}
	default:
		sampleFlows = []models.TrafficFlow{
			{
				ServerIP: sess.ServerIP, ServerID: sess.ServerID, ServerHostname: sess.ServerHostname, GroupIDs: sess.GroupIDs,
				Method: "GET", Scheme: "https", Host: "github.com", Path: "/microsoft/onnxruntime/releases/download/v1.19.2/onnxruntime-linux-x64-gpu-1.19.2.tgz",
				FullURL: "https://github.com/microsoft/onnxruntime/releases/download/v1.19.2/onnxruntime-linux-x64-gpu-1.19.2.tgz", UserAgent: "curl/8.5.0",
				Verdict: "LEARNING_ALLOWED", StatusCode: 302, RedirectLocation: "https://objects.githubusercontent.com/github-production-release-asset-2e65be/156939672/onnxruntime-gpu.tgz",
				LatencyMs: 36, TLSIntercepted: true, SessionID: sess.ID, Timestamp: now,
			},
			{
				ServerIP: sess.ServerIP, ServerID: sess.ServerID, ServerHostname: sess.ServerHostname, GroupIDs: sess.GroupIDs,
				Method: "GET", Scheme: "https", Host: "objects.githubusercontent.com", Path: "/github-production-release-asset-2e65be/156939672/onnxruntime-gpu.tgz",
				FullURL: "https://objects.githubusercontent.com/github-production-release-asset-2e65be/156939672/onnxruntime-gpu.tgz", UserAgent: "curl/8.5.0",
				Verdict: "LEARNING_ALLOWED", StatusCode: 200, RedirectParentURL: "https://github.com/microsoft/onnxruntime/releases/download/v1.19.2/onnxruntime-linux-x64-gpu-1.19.2.tgz",
				LatencyMs: 145, TLSIntercepted: true, SessionID: sess.ID, Timestamp: now,
			},
			{
				ServerIP: sess.ServerIP, ServerID: sess.ServerID, ServerHostname: sess.ServerHostname, GroupIDs: sess.GroupIDs,
				Method: "GET", Scheme: "https", Host: "codeload.github.com", Path: "/microsoft/DeepSpeed/tar.gz/refs/tags/v0.15.1",
				FullURL: "https://codeload.github.com/microsoft/DeepSpeed/tar.gz/refs/tags/v0.15.1", UserAgent: "git/2.43.0",
				Verdict: "LEARNING_ALLOWED", StatusCode: 200, LatencyMs: 88, TLSIntercepted: true, SessionID: sess.ID, Timestamp: now,
			},
		}
	}

	return sampleFlows
}
