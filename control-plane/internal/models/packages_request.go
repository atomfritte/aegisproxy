package models

import "time"

// Package request and dependency-graph model (3.0). A request resolves a package to its full
// dependency graph, assesses every node, shows the result for review, and on approval creates the
// PackageApprovals for the whole graph.

// Request states.
const (
	PackageReqResolving = "resolving" // fetching metadata and resolving the dependency graph
	PackageReqAnalyzing = "analyzing" // advisory lookup, signature/provenance checks, sandbox jobs running
	PackageReqReady     = "ready"     // assessment complete, waiting for a decision
	PackageReqApproved  = "approved"  // approved; approvals created for the graph
	PackageReqRejected  = "rejected"
	PackageReqFailed    = "failed" // resolution or analysis could not complete
)

// PackageRequest is a request to approve a package (and its dependency graph) for a set of groups.
type PackageRequest struct {
	ID          string `json:"id"`
	Ecosystem   string `json:"ecosystem"`
	Name        string `json:"name"`         // normalized
	DisplayName string `json:"display_name"` // as requested
	// Requested is the version or range the requester asked for; Version is the concrete root version
	// the resolver selected.
	Requested string   `json:"requested"`
	Version   string   `json:"version"`
	GroupIDs  []string `json:"group_ids"`
	Status    string   `json:"status"`
	// Origin: manual (a reviewer opened it), discovered (a client download triggered it), rule (a rule
	// is approving an update), watch (the watch loop found a new version).
	Origin      string    `json:"origin"`
	RequestedBy string    `json:"requested_by"`
	Reason      string    `json:"reason,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// Graph is the resolved dependency graph (root first). Empty while resolving.
	Graph []PackageNode `json:"graph,omitempty"`
	// RootKey is the graph key (name@version) of the requested package.
	RootKey string `json:"root_key,omitempty"`
	// Risk is the highest node risk; Counts summarizes node states for the list view.
	Risk   string         `json:"risk,omitempty"`
	Counts map[string]int `json:"counts,omitempty"`
	Error  string         `json:"error,omitempty"`
	// Decision records the review.
	DecidedBy    string     `json:"decided_by,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	Decision     string     `json:"decision,omitempty"` // approve | reject
	DecisionNote string     `json:"decision_note,omitempty"`
	// AutoDecision names the rule that decided without a human (if any).
	AutoRuleID   string `json:"auto_rule_id,omitempty"`
	AutoRuleName string `json:"auto_rule_name,omitempty"`
}

// PackageNode is one package version in a resolved graph.
type PackageNode struct {
	Key         string `json:"key"` // ecosystem:name@version
	Ecosystem   string `json:"ecosystem"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Version     string `json:"version"`
	Root        bool   `json:"root,omitempty"`
	Direct      bool   `json:"direct,omitempty"` // a direct dependency of the root
	// RequiredBy are the parent node keys that pulled this node in, each with the range they asked for.
	RequiredBy  []PackageEdge    `json:"required_by,omitempty"`
	Kinds       []string         `json:"kinds,omitempty"` // runtime, dev, optional, peer, build, framework
	Files       []PackageFilePin `json:"files,omitempty"`
	PublishedAt *time.Time       `json:"published_at,omitempty"`
	License     string           `json:"license,omitempty"`
	Deprecated  bool             `json:"deprecated,omitempty"`
	Yanked      bool             `json:"yanked,omitempty"`
	// State of this node relative to the current approvals: approved | blocked | new | update.
	State string `json:"state"`
	// AlreadyApprovedID is the existing approval covering this node (State approved).
	AlreadyApprovedID string `json:"already_approved_id,omitempty"`
	// Assessment is the risk assessment of this exact version.
	Assessment *PackageAssessment `json:"assessment,omitempty"`
}

// PackageEdge records who required a node and with what range.
type PackageEdge struct {
	Parent string `json:"parent"` // parent node key ("" for the root request)
	Range  string `json:"range"`
	Kind   string `json:"kind,omitempty"`
}
