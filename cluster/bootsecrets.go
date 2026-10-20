package cluster

// The boot secrets are the key pair Sealed Secrets starts with, the owner's sealed App key, and the Job that
// initialises OpenBao on a cluster that hosts the platform.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"text/template"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	SealedSecretsCertFile = "sealed-secrets.crt"
	// SealedAppKeyFile sits in cluster/, so Argo CD applies a newly sealed key once it can read the repository.
	SealedAppKeyFile = "cluster/github-app-key.sealed.yaml"

	sealedSecretsKeyBits = 3072
	sealedSecretsCertFor = 10 * 365 * 24 * time.Hour

	bootNamespace    = "mitstack-node"
	sealedAppKeyName = "github-app-key"
	sealedAppKeyItem = "private-key"
)

var encryptedDataRe = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)

// SealedSecretsInputs are the key pair and the owner's sealed App key a node that hosts the platform boots with.
type SealedSecretsInputs struct {
	KeyPEM, CertPEM string
	SealedAppKey    SealedSecret
}

// SealedSecret is a Bitnami SealedSecret as the owner commits it.
type SealedSecret struct {
	APIVersion string           `yaml:"apiVersion"`
	Kind       string           `yaml:"kind"`
	Metadata   ObjectMeta       `yaml:"metadata"`
	Spec       SealedSecretSpec `yaml:"spec"`
}

// SealedSecretSpec holds a SealedSecret's sealed values and the metadata of the Secret it opens to.
type SealedSecretSpec struct {
	EncryptedData map[string]string `yaml:"encryptedData"`
	Template      struct {
		Metadata ObjectMeta `yaml:"metadata"`
	} `yaml:"template"`
}

// MintSealedSecretsKeyPair makes the RSA pair and self-signed certificate the controller would make for itself.
func MintSealedSecretsKeyPair() (keyPEM, certPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, sealedSecretsKeyBits)
	if err != nil {
		return "", "", fmt.Errorf("minting the Sealed Secrets key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("minting the Sealed Secrets certificate: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "sealed-secret", Organization: []string{"sealed-secret"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(sealedSecretsCertFor),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("minting the Sealed Secrets certificate: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return keyPEM, certPEM, nil
}

// keyPairOf answers an error unless keyPEM is the RSA key whose public half certPEM certifies.
func keyPairOf(keyPEM, certPEM string) error {
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	certBlock, _ := pem.Decode([]byte(certPEM))
	if keyBlock == nil || certBlock == nil {
		return fmt.Errorf("the Sealed Secrets key or certificate is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("the Sealed Secrets key is not a PKCS #1 RSA key: %w", err)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("the Sealed Secrets certificate does not parse: %w", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return fmt.Errorf("the Sealed Secrets certificate certifies another key")
	}
	return nil
}

// ReadSealedAppKey keeps only the App's sealed key from the owner's file, since k3s applies the user data's
// manifests with cluster-admin rights.
func ReadSealedAppKey(content string) (SealedSecret, error) {
	dec := yaml.NewDecoder(strings.NewReader(content))
	var s SealedSecret
	if err := dec.Decode(&s); err != nil {
		return SealedSecret{}, sealedAppKeyError("it is not YAML: %v", err)
	}
	var extra any
	if dec.Decode(&extra) == nil {
		return SealedSecret{}, sealedAppKeyError("it holds more than one document")
	}
	m := s.Metadata
	if s.APIVersion != "bitnami.com/v1alpha1" || s.Kind != "SealedSecret" || m.Name != sealedAppKeyName || m.Namespace != bootNamespace {
		return SealedSecret{}, sealedAppKeyError("it is %s %s %s/%s, want bitnami.com/v1alpha1 SealedSecret %s/%s",
			s.APIVersion, s.Kind, m.Namespace, m.Name, bootNamespace, sealedAppKeyName)
	}
	data := s.Spec.EncryptedData[sealedAppKeyItem]
	if len(s.Spec.EncryptedData) != 1 || !encryptedDataRe.MatchString(data) {
		return SealedSecret{}, sealedAppKeyError("its encryptedData holds %d keys, want only %s, sealed", len(s.Spec.EncryptedData), sealedAppKeyItem)
	}
	app := SealedSecret{APIVersion: s.APIVersion, Kind: s.Kind, Metadata: ObjectMeta{Name: m.Name, Namespace: m.Namespace},
		Spec: SealedSecretSpec{EncryptedData: map[string]string{sealedAppKeyItem: data}}}
	app.Spec.Template.Metadata = ObjectMeta{Name: m.Name, Namespace: m.Namespace}
	return app, nil
}

// opens answers an error unless the pair's key opens the App's key, sealed in kubeseal's strict scope.
func (in SealedSecretsInputs) Opens(app SealedSecret) error {
	block, _ := pem.Decode([]byte(in.KeyPEM))
	if block == nil {
		return fmt.Errorf("the Sealed Secrets key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("the Sealed Secrets key is not a PKCS #1 RSA key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(app.Spec.EncryptedData[sealedAppKeyItem])
	if err != nil || len(raw) < 2 || len(raw) < 2+int(binary.BigEndian.Uint16(raw)) {
		return sealedAppKeyError("its %s is not a sealed value", sealedAppKeyItem)
	}
	if err := openSealed(key, raw, []byte(app.Metadata.Namespace+"/"+app.Metadata.Name)); err != nil {
		return sealedAppKeyError("it is not sealed against this install's %s", SealedSecretsCertFile)
	}
	return nil
}

// openSealed opens raw as the controller does: a length-prefixed RSA-OAEP session key bound to label, then AES-GCM
// with a zero nonce.
func openSealed(key *rsa.PrivateKey, raw, label []byte) error {
	n := 2 + int(binary.BigEndian.Uint16(raw))
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), nil, key, raw[2:n], label)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	_, err = gcm.Open(nil, make([]byte, gcm.NonceSize()), raw[n:], nil)
	return err
}

func sealedAppKeyError(format string, args ...any) error {
	return fmt.Errorf("%s cannot be booted from: "+format, append([]any{SealedAppKeyFile}, args...)...)
}

type tlsSecret struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   ObjectMeta        `yaml:"metadata"`
	Type       string            `yaml:"type"`
	StringData map[string]string `yaml:"stringData"`
}

// sealedSecretsKeySecret is the controller's own key pair, which it takes as active by its label.
func sealedSecretsKeySecret(s SealedSecretsInputs) tlsSecret {
	return tlsSecret{APIVersion: "v1", Kind: "Secret", Type: "kubernetes.io/tls",
		Metadata:   ObjectMeta{Name: "sealed-secrets-key", Namespace: "kube-system", Labels: map[string]string{"sealedsecrets.bitnami.com/sealed-secrets-key": "active"}},
		StringData: map[string]string{"tls.crt": s.CertPEM, "tls.key": s.KeyPEM}}
}

// openBaoBootTemplate runs the init once and the two writers, the only pods holding a service account token, from the node agent's image,
// each verifying OpenBao against the authority trust-manager copies into the ConfigMap openbao-ca.
var openBaoBootTemplate = template.Must(template.New("openbao-boot").Parse(`apiVersion: v1
kind: Namespace
metadata:
  name: mitstack-node
  labels:
    pod-security.kubernetes.io/enforce: privileged
---
{{.SealedAppKey}}---
apiVersion: v1
kind: ConfigMap
metadata:
  name: openbao-recipient
  namespace: mitstack-node
data:
  recipient.asc: |
{{.Recipient}}---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: openbao-init
  namespace: mitstack-node
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: github-app-writer
  namespace: mitstack-node
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-secrets-writer
  namespace: mitstack-node
---
apiVersion: batch/v1
kind: Job
metadata:
  name: openbao-init
  namespace: mitstack-node
spec:
  backoffLimit: 3
  template:
    metadata:
      labels:
        mitstack.dev/app: openbao-init
    spec:
      restartPolicy: Never
      serviceAccountName: openbao-init
{{.Pod}}      containers:
        - name: init
          command: [mitstack-openbao, init]
{{.Container}}          env:
            - {name: MITSTACK_REPOSITORY, value: "{{.Repository}}"}
            - {name: MITSTACK_GITHUB_APP_ID, value: "{{.AppID}}"}
            - {name: MITSTACK_GITHUB_INSTALLATION_ID, value: "{{.InstallationID}}"}
            - {name: GNUPGHOME, value: /tmp/gnupg}
          volumeMounts:
            - {name: recipient, mountPath: /etc/mitstack/recipient, readOnly: true}
            - {name: github-app, mountPath: /etc/mitstack/github-app, readOnly: true}
            - {name: tmp, mountPath: /tmp}
            - {name: openbao-ca, mountPath: /etc/mitstack/openbao-ca, readOnly: true}
      volumes:
        - {name: recipient, configMap: {name: openbao-recipient}}
        - {name: github-app, secret: {secretName: github-app-key, defaultMode: 0440}}
        - {name: tmp, emptyDir: {medium: Memory, sizeLimit: 16Mi}}
        - {name: openbao-ca, configMap: {name: openbao-ca}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: github-app-writer
  namespace: mitstack-node
spec:
  replicas: 1
  selector:
    matchLabels:
      mitstack.dev/app: github-app-writer
  template:
    metadata:
      labels:
        mitstack.dev/app: github-app-writer
    spec:
      serviceAccountName: github-app-writer
{{.Pod}}      containers:
        - name: writer
          command: [mitstack-openbao, write-app-key]
{{.Container}}          volumeMounts:
            - {name: github-app, mountPath: /etc/mitstack/github-app, readOnly: true}
            - {name: openbao-ca, mountPath: /etc/mitstack/openbao-ca, readOnly: true}
      volumes:
        - {name: github-app, secret: {secretName: github-app-key, defaultMode: 0440}}
        - {name: openbao-ca, configMap: {name: openbao-ca}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-secrets-writer
  namespace: mitstack-node
spec:
  replicas: 1
  selector:
    matchLabels:
      mitstack.dev/app: app-secrets-writer
  template:
    metadata:
      labels:
        mitstack.dev/app: app-secrets-writer
    spec:
      serviceAccountName: app-secrets-writer
{{.Pod}}      containers:
        - name: writer
          command: [mitstack-openbao, write-app-secrets]
{{.Container}}          volumeMounts:
            - {name: app-secrets, mountPath: /etc/mitstack/app-secrets, readOnly: true}
            - {name: openbao-ca, mountPath: /etc/mitstack/openbao-ca, readOnly: true}
      volumes:
        - {name: app-secrets, secret: {secretName: app-secrets, optional: true, defaultMode: 0440}}
        - {name: openbao-ca, configMap: {name: openbao-ca}}
`))

const (
	bootPodSpec = `      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
`
	bootContainerSpec = `          image: %s
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          resources:
            requests: {cpu: 10m, memory: 32Mi}
            limits: {cpu: 200m, memory: 128Mi}
`
)

// openBaoBootManifest is the namespace, the owner's sealed App key, the init Job and the two writers.
func openBaoBootManifest(repoURL string, h HostsPlatformInputs) (string, error) {
	sealed, err := marshalYAML(h.SealedSecrets.SealedAppKey)
	if err != nil {
		return "", fmt.Errorf("rendering the sealed App key: %w", err)
	}
	var indented strings.Builder
	for _, line := range strings.SplitAfter(strings.TrimRight(h.Recipient, "\n")+"\n", "\n") {
		if line != "" {
			indented.WriteString("    " + line)
		}
	}
	repo := githubRepoURLRe.FindStringSubmatch(repoURL)
	var b bytes.Buffer
	err = openBaoBootTemplate.Execute(&b, map[string]string{
		"SealedAppKey": sealed, "Recipient": indented.String(), "Repository": repo[1] + "/" + repo[2],
		"AppID": h.AppID, "InstallationID": h.InstallationID, "Pod": bootPodSpec, "Container": fmt.Sprintf(bootContainerSpec, nodeAgentImage),
	})
	if err != nil {
		return "", fmt.Errorf("rendering OpenBao's boot Job: %w", err)
	}
	return b.String(), nil
}
