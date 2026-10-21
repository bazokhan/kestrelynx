package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/kubework"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/runner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// workKubernetesEntrypoint is the program the work container of a work Pod
// runs: the same program as in Docker, in the mode that reports through the
// sealed log.
var workKubernetesEntrypoint = []string{worker.ProgramPath, "run-kubernetes", worker.JobFile}

// digestRefRE is a reference pinned by digest.
var digestRefRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)

// ownContainerName is the name of the container KestreLynx runs in when its
// Pod has several; with a single container no name is needed.
const ownContainerName = "kestrelynx"

// kubernetesLanguageConfig is the language update stage on Kubernetes. Without
// a work namespace in the configuration no work Pod can be made, and the update
// candidates are reported as manual; with one, jobs run in work Pods.
func kubernetesLanguageConfig(cfg config.Config, log *slog.Logger) *runner.LanguageUpdateConfig {
	k := cfg.Remediation.Worker.Kubernetes
	if k.Namespace == "" {
		return &runner.LanguageUpdateConfig{Unavailable: &runner.LanguageUnavailable{
			Reason: remediation.ReasonWorkNamespaceNotConfigured, Manual: true,
			Detail: "language package updates on Kubernetes run in work Pods, and remediation.worker.kubernetes.namespace is not set",
		}}
	}
	if k.RuntimeClass != "" {
		// A RuntimeClass can add overhead to a Pod and change what runs it; the
		// work Pod check and the admission policy have no rule for either, so
		// no work Pod is made while one is configured.
		return &runner.LanguageUpdateConfig{Unavailable: &runner.LanguageUnavailable{
			Reason: remediation.ReasonWorkRuntimeClassUnsupported, Manual: true,
			Detail: "remediation.worker.kubernetes.runtime_class is set; work Pods do not support a RuntimeClass, so remove it",
		}}
	}
	return buildKubernetesLanguageConfig(cfg, log)
}

// buildKubernetesLanguageConfig assembles the dependency update stage that
// runs jobs in work Pods. A problem that stops every update is returned as the
// reason the cycle's update candidates are deferred with.
func buildKubernetesLanguageConfig(cfg config.Config, log *slog.Logger) *runner.LanguageUpdateConfig {
	rc := cfg.Remediation
	k := rc.Worker.Kubernetes
	unavailable := func(detail string, err error) *runner.LanguageUpdateConfig {
		log.Warn("language package updates are disabled", "reason", remediation.ReasonWorkImageUnavailable, "detail", detail, "err", err)
		return &runner.LanguageUpdateConfig{Unavailable: &runner.LanguageUnavailable{Reason: remediation.ReasonWorkImageUnavailable, Detail: detail}}
	}
	goarch := runtime.GOARCH
	program, err := programLoader(rc.Worker.ProgramDir, goarch)
	switch {
	case errors.Is(err, errNoProgramHash):
		return &runner.LanguageUpdateConfig{Unavailable: &runner.LanguageUnavailable{
			Reason: remediation.ReasonWorkImageNotConfigured, Detail: "this build carries no work program and remediation.worker.program_dir is not set"}}
	case err != nil:
		return unavailable("the work program is missing or is not the one this build was released with", err)
	}
	if _, err := program(); err != nil {
		return unavailable("the work program is missing or is not the one this build was released with", err)
	}
	if toolSupplyFactory == nil {
		return unavailable("this build has no package manager provider", nil)
	}
	tools, err := toolSupplyFactory(cfg, log)
	if err != nil {
		return unavailable("the package manager provider could not be set up", err)
	}
	id, err := docker.LoadOrCreateInstanceID(rc.StorageDir)
	if err != nil {
		return unavailable("the instance id of the work Pods could not be read or created", err)
	}
	session, err := newSessionID()
	if err != nil {
		return unavailable("the session id of the work Pods could not be made", err)
	}
	images := map[string]string{}
	for _, rid := range remediation.DefaultRuntimeIDs() {
		spec, ok := worker.LookupRuntime(rid)
		if !ok || !spec.HasImage() {
			return unavailable("the runtime "+rid+" is not in the table of this build", nil)
		}
		images[rid] = kubernetesWorkImageRef(spec, rc.Worker.Registry)
	}

	kc := cfg.Kubernetes
	api, err := kubework.New(kubework.Options{
		APIServer: kc.APIServer, TokenFile: kc.TokenFile, CAFile: kc.CAFile, TLSServerName: kc.TLSServerName,
		Namespace: k.Namespace, Log: log,
	})
	if err != nil {
		return unavailable("the Kubernetes client for the work Pods could not be set up", err)
	}
	receiver := k.ReceiverImage
	if receiver == "" {
		receiver, err = ownImage(kc, log)
		if err != nil {
			return unavailable("the image of the receiving init container could not be found; set remediation.worker.kubernetes.receiver_image", err)
		}
	}
	limits := workTransferLimits()
	rn, err := kubework.NewRunner(kubework.Config{
		API: api, Namespace: k.Namespace, ServiceAccount: k.ServiceAccount, PriorityClass: k.PriorityClass,
		Arch: goarch, ReceiverImage: receiver, Images: images,
		Entrypoint: workKubernetesEntrypoint, Env: workEnv, InstanceID: id, SessionID: session,
		MaxConcurrent: k.MaxConcurrentPods, Limits: limits,
		MaxResultTarBytes: worker.DefaultResultLimits().MaxTarBytes, Log: log,
	})
	if err != nil {
		return unavailable("the work Pod runner could not be set up", err)
	}
	// Work Pods that an earlier run left are removed at once and then
	// regularly, whether or not any job runs.
	go rn.RunCollector(context.Background(), 0)

	platform := "linux/" + goarch
	l := rc.Limits
	log.Info("language package updates enabled on Kubernetes", "namespace", k.Namespace, "runtimes", len(images), "platform", platform,
		"max_concurrent_pods", k.MaxConcurrentPods, "dependency_jobs_per_cycle", l.DependencyJobsPerCycle, "job_timeout", l.JobTimeout)
	var _ remediation.WorkRunner = rn
	return &runner.LanguageUpdateConfig{
		NewUpdater: func(ctx context.Context, in runner.LanguageUpdateInput) (runner.LanguageUpdater, error) {
			// The admission policy of the work namespace is checked at the
			// start of every cycle; without it nothing is started.
			if problem := rn.VerifyAdmission(ctx); problem != nil {
				return nil, problem
			}
			return newLanguageUpdater(cfg, tools, rn, platform, program, in)
		},
	}
}

// kubernetesWorkImageRef is the reference a work Pod names its image by: always
// with the registry host, because the admission policy compares the whole
// repository, and a short name would be read differently by each node's
// container runtime.
func kubernetesWorkImageRef(spec worker.RuntimeSpec, mirror string) string {
	if mirror == "" {
		return "docker.io/library/" + spec.ImageRef()
	}
	return workImageRef(spec, mirror)
}

// newSessionID makes the identifier of this start of the process; work Pods of
// another session are leftovers.
func newSessionID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ownImage finds the image, pinned by digest, that this process's own Pod
// runs, for the receiving init container to use.
func ownImage(kc config.KubernetesConfig, log *slog.Logger) (string, error) {
	tokenDir := filepath.Dir(kc.TokenFile)
	if kc.TokenFile == "" {
		tokenDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	}
	ns, err := os.ReadFile(filepath.Join(tokenDir, "namespace"))
	if err != nil {
		return "", fmt.Errorf("read the namespace of this Pod: %w", err)
	}
	pod := os.Getenv("HOSTNAME")
	if pod == "" {
		return "", errors.New("HOSTNAME does not name this Pod")
	}
	c, err := kubework.New(kubework.Options{
		APIServer: kc.APIServer, TokenFile: kc.TokenFile, CAFile: kc.CAFile, TLSServerName: kc.TLSServerName,
		Namespace: strings.TrimSpace(string(ns)), Log: log,
	})
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), workCleanupTimeout)
	defer cancel()
	id, err := c.OwnImageID(ctx, pod, ownContainerName)
	if err != nil {
		if _, err2 := c.OwnImageID(ctx, pod, ""); err2 == nil {
			id, err = c.OwnImageID(ctx, pod, "")
		}
	}
	if err != nil {
		return "", err
	}
	for _, p := range []string{"docker-pullable://", "docker://"} {
		id = strings.TrimPrefix(id, p)
	}
	if !digestRefRE.MatchString(id) {
		return "", fmt.Errorf("the image ID %q of this Pod is not a reference pinned by digest", id)
	}
	return id, nil
}
