package cluster

// A cluster runs components copied into its repository from a cluster-bases release, since Argo CD holds a token only for the cluster's own repositories.

import (
	"embed"
	"fmt"
	"maps"
	"path"
)

const (
	clusterBasesTag = "v0.5.0"

	seedLocalPVLVMFile = "cluster/localpv-lvm.yaml"
	localPVLVMDir      = "cluster-bases/localpv-lvm"
	localPVLVMSource   = "clusterbases/localpv-lvm"
)

//go:embed clusterbases/localpv-lvm/*.yaml clusterbases/cloudnative-pg/*.yaml
var clusterBases embed.FS

// RenderDedicatedSeed is the Cloud seed with LocalPV-LVM added, the storage only a dedicated server has a volume group for.
func RenderDedicatedSeed(v Versions, publicIPv4, repoURL string) (map[string]string, error) {
	files, err := RenderSeed(v, publicIPv4, repoURL)
	if err != nil {
		return nil, err
	}
	storage, err := componentSeedFiles(localPVLVMSource, localPVLVMDir, seedLocalPVLVMFile, localPVLVMApplication(repoURL))
	if err != nil {
		return nil, err
	}
	maps.Copy(files, storage)
	return files, nil
}

func componentSeedFiles(source, dir, appFile string, app argoApplication) (map[string]string, error) {
	entries, err := clusterBases.ReadDir(source)
	if err != nil {
		return nil, fmt.Errorf("rendering %s: %w", dir, err)
	}
	files := make(map[string]string, len(entries)+1)
	for _, e := range entries {
		content, err := clusterBases.ReadFile(path.Join(source, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("rendering %s: %w", dir, err)
		}
		files[path.Join(dir, e.Name())] = string(content)
	}
	rendered, err := marshalYAML(app)
	if err != nil {
		return nil, fmt.Errorf("rendering %s: %w", appFile, err)
	}
	files[appFile] = rendered
	return files, nil
}

// clusterBasesApplication syncs a copied component from the cluster's own repository in crdWave, so the CRDs and storage class it installs exist before a wave-0 resource uses them.
func clusterBasesApplication(name, dir, namespace, repoURL string) argoApplication {
	app := inCRDWave(argoApplication{
		APIVersion: "argoproj.io/v1alpha1",
		Kind:       "Application",
		Metadata:   ObjectMeta{Name: name, Namespace: "argocd"},
		Spec: argoAppSpec{
			Project:     "default",
			Source:      argoSource{RepoURL: repoURL, Path: dir, TargetRevision: "HEAD"},
			Destination: argoDestination{Server: inClusterServer, Namespace: namespace},
			SyncPolicy:  argoSyncPolicy{Automated: argoAutomated{Prune: true, SelfHeal: true}},
		},
	})
	app.Metadata.Annotations["mitstack.dev/cluster-bases-tag"] = clusterBasesTag
	return app
}

// localPVLVMApplication goes into kube-system, the namespace the admission policies leave alone for its privileged node plugin.
func localPVLVMApplication(repoURL string) argoApplication {
	return clusterBasesApplication("localpv-lvm", localPVLVMDir, "kube-system", repoURL)
}
