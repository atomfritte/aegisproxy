package store

import (
	"errors"
	"sort"
	"time"

	"aegisproxy/control-plane/internal/models"
)

const analysisLeaseSeconds = 900

// EnqueueAnalysis adds a sandbox analysis job for an artifact, unless an equivalent job is already
// queued/running or a completed assessment with a sandbox result already exists. Returns the job ID
// (existing or new) and whether a new job was created.
func (s *Store) EnqueueAnalysis(job models.AnalysisJob) (string, bool, error) {
	var id string
	var created bool
	err := s.withWrite(func() error {
		for _, j := range s.state.PackageWork.Jobs {
			if j.Ecosystem == job.Ecosystem && j.Name == job.Name && j.Version == job.Version && j.Filename == job.Filename &&
				(j.State == models.AnalysisQueued || j.State == models.AnalysisRunning) {
				id = j.ID
				return nil
			}
		}
		job.ID = newRandomID("pjob")
		job.State = models.AnalysisQueued
		job.CreatedAt = time.Now().UTC()
		if len(s.state.PackageWork.Jobs) >= maxAnalysisJobs {
			s.pruneJobsLocked()
		}
		s.state.PackageWork.Jobs = append(s.state.PackageWork.Jobs, job)
		id, created = job.ID, true
		s.bumpConfigLocked()
		return nil
	})
	return id, created, err
}

// ClaimAnalysis leases the oldest queued job matching the worker's drivers/ecosystems (ecosystems
// empty = any). Returns nil when the queue is empty.
func (s *Store) ClaimAnalysis(worker string, ecosystems []string) (*models.AnalysisJob, error) {
	ecoOK := func(e string) bool {
		if len(ecosystems) == 0 {
			return true
		}
		for _, x := range ecosystems {
			if x == e {
				return true
			}
		}
		return false
	}
	var claimed *models.AnalysisJob
	err := s.withWrite(func() error {
		now := time.Now().UTC()
		// Reclaim expired leases first.
		for i := range s.state.PackageWork.Jobs {
			j := &s.state.PackageWork.Jobs[i]
			if j.State == models.AnalysisRunning && j.LeaseUntil != nil && now.After(*j.LeaseUntil) {
				j.State = models.AnalysisQueued
				j.Worker = ""
			}
		}
		idx := -1
		for i := range s.state.PackageWork.Jobs {
			j := s.state.PackageWork.Jobs[i]
			if j.State == models.AnalysisQueued && ecoOK(j.Ecosystem) {
				if idx == -1 || j.CreatedAt.Before(s.state.PackageWork.Jobs[idx].CreatedAt) {
					idx = i
				}
			}
		}
		if idx == -1 {
			return nil
		}
		j := &s.state.PackageWork.Jobs[idx]
		lease := now.Add(analysisLeaseSeconds * time.Second)
		j.State, j.Worker, j.LeasedAt, j.LeaseUntil, j.Attempts = models.AnalysisRunning, worker, &now, &lease, j.Attempts+1
		cp := *j
		claimed = &cp
		s.bumpConfigLocked()
		return nil
	})
	return claimed, err
}

// HeartbeatAnalysis extends a job's lease.
func (s *Store) HeartbeatAnalysis(id, worker string) error {
	return s.withWrite(func() error {
		for i := range s.state.PackageWork.Jobs {
			j := &s.state.PackageWork.Jobs[i]
			if j.ID == id && j.Worker == worker && j.State == models.AnalysisRunning {
				lease := time.Now().UTC().Add(analysisLeaseSeconds * time.Second)
				j.LeaseUntil = &lease
				s.bumpConfigLocked()
				return nil
			}
		}
		return errors.New("job not found or not leased to this worker")
	})
}

// CompleteAnalysis records a job's outcome (reportKey set on success, err on failure).
func (s *Store) CompleteAnalysis(id, worker, reportKey, failure string) (*models.AnalysisJob, error) {
	var out *models.AnalysisJob
	err := s.withWrite(func() error {
		for i := range s.state.PackageWork.Jobs {
			j := &s.state.PackageWork.Jobs[i]
			if j.ID != id {
				continue
			}
			now := time.Now().UTC()
			j.FinishedAt = &now
			j.LeaseUntil = nil
			if failure != "" {
				j.State, j.Error = models.AnalysisFailed, failure
			} else {
				j.State, j.ReportKey = models.AnalysisCompleted, reportKey
			}
			cp := *j
			out = &cp
			s.bumpConfigLocked()
			return nil
		}
		return errors.New("job not found")
	})
	return out, err
}

// AnalysisJob returns one job by ID.
func (s *Store) AnalysisJob(id string) (models.AnalysisJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, j := range s.state.PackageWork.Jobs {
		if j.ID == id {
			return j, true
		}
	}
	return models.AnalysisJob{}, false
}

// AnalysisJobs returns the jobs, newest first.
func (s *Store) AnalysisJobs() []models.AnalysisJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]models.AnalysisJob(nil), s.state.PackageWork.Jobs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *Store) pruneJobsLocked() {
	jobs := s.state.PackageWork.Jobs
	sort.SliceStable(jobs, func(i, j int) bool { return jobs[i].CreatedAt.Before(jobs[j].CreatedAt) })
	kept := jobs[:0]
	dropped := 0
	target := len(jobs) - maxAnalysisJobs + 1
	for _, j := range jobs {
		if dropped < target && (j.State == models.AnalysisCompleted || j.State == models.AnalysisFailed) {
			dropped++
			continue
		}
		kept = append(kept, j)
	}
	s.state.PackageWork.Jobs = kept
}
