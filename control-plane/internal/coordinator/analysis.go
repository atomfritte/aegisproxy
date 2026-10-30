package coordinator

import (
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages"
	"aegisproxy/control-plane/internal/sandbox"
)

// OnAnalysisResult records a finished sandbox job: it stores the raw report, folds the summary into
// the version's assessment and re-processes the requests that were waiting on it.
func (c *Coordinator) OnAnalysisResult(jobID string, report *sandbox.Report, failure string) {
	job, ok := c.store.AnalysisJob(jobID)
	if !ok {
		return
	}
	reportKey := ""
	if report != nil && failure == "" {
		reportKey = jobID
		if err := c.reports.Put(reportKey, report); err != nil {
			c.log.Warn("could not store sandbox report", "job", jobID, "error", err)
			reportKey = ""
		}
	}
	finished, err := c.store.CompleteAnalysis(jobID, job.Worker, reportKey, failure)
	if err != nil {
		c.log.Warn("could not complete analysis job", "job", jobID, "error", err)
		return
	}

	// Merge the result into the assessment of the analyzed version.
	a := c.store.Assessment(job.Ecosystem, normalizedJobName(job), job.Version)
	if a == nil {
		a = &models.PackageAssessment{Ecosystem: job.Ecosystem, Name: normalizedJobName(job), Version: job.Version}
	}
	if failure != "" {
		a.Sandbox = &models.PackageSandboxResult{JobID: jobID, Status: models.AnalysisFailed, Error: failure}
		a.Partial = true
	} else if report != nil {
		res, findings := packages.SummarizeReport(report, reportKey)
		res.JobID = jobID
		c.svc.MergeSandbox(a, res, findings)
	}
	_ = finished
	c.store.PutAssessment(*a)

	// Re-evaluate requests still resolving/analyzing (they may now be decidable).
	c.Kick("")
}

// normalizedJobName maps a job's display name back to the normalized form used as the assessment key.
func normalizedJobName(job models.AnalysisJob) string {
	return registryNormalize(job.Ecosystem, job.Name)
}
