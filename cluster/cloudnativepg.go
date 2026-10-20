package cluster

import _ "embed"

const (
	seedCloudNativePGFile = "cluster/cloudnative-pg.yaml"
	cloudNativePGDir      = "cluster-bases/cloudnative-pg"
	cloudNativePGSource   = "clusterbases/cloudnative-pg"
	cloudNativePGNS       = "cnpg-system"

	seedDatabaseSlicesPolicyFile = "cluster/network-policy-mitstack-database-slices.yaml"
)

//go:embed network-policies/mitstack-database-slices.yaml
var databaseSlicesPolicy string

func cloudNativePGSeedFiles(repoURL string) (map[string]string, error) {
	files, err := componentSeedFiles(cloudNativePGSource, cloudNativePGDir, seedCloudNativePGFile, cloudNativePGApplication(repoURL))
	if err != nil {
		return nil, err
	}
	files[seedDatabaseSlicesPolicyFile] = databaseSlicesPolicy
	return files, nil
}

// cloudNativePGApplication applies server-side, since CloudNativePG's CRDs are larger than the annotation a client-side apply writes.
func cloudNativePGApplication(repoURL string) argoApplication {
	app := clusterBasesApplication("cloudnative-pg", cloudNativePGDir, cloudNativePGNS, repoURL)
	app.Spec.SyncPolicy.SyncOptions = []string{"ServerSideApply=true"}
	return app
}
