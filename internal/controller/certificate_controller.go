/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	certscontrollerkuberasticcomv1 "certscontroller.kuberastic.com/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)


func GenerateCertTemplate(domain string, organization string, validityInMonths int) x509.Certificate {
	return x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, validityInMonths, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func GenerateSelfSignedCert(domain string, organization string, validityInMonths int) (string, string, error) {

	var certsSB strings.Builder
	var privkeySB strings.Builder

	certTemplate := GenerateCertTemplate(domain, organization, validityInMonths)
	privateKey, err := GenerateKey()
	if err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}

	// Create the self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}

	// Encode and write the certificate in PEM format
	if err := pem.Encode(&certsSB, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}

	// Marshal private key and write it in PEM format
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}
	if err := pem.Encode(&privkeySB, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}

	log.Log.Info("Self-signed certificate generated: %s.crt and %s.key", domain, domain)
	return certsSB.String(), privkeySB.String(), nil
}

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=certscontroller.kuberastic.com.certscontroller.kuberastic.com,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certscontroller.kuberastic.com.certscontroller.kuberastic.com,resources=certificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certscontroller.kuberastic.com.certscontroller.kuberastic.com,resources=certificates/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Certificate object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	certificate := certscontrollerkuberasticcomv1.Certificate{}
	foundSecret := corev1.Secret{}

	certNotFoundError := r.Get(ctx, req.NamespacedName, &certificate)
	secretNotFoundError := r.Get(ctx, types.NamespacedName{Name: certificate.Spec.SecretRef.Name, Namespace: certificate.Namespace}, &foundSecret)

	cert, privKey, err := GenerateSelfSignedCert(certificate.Spec.Domain, certificate.Spec.Org, certificate.Spec.ValidityInMonths)
	if err != nil {
		log.Log.Error(err, "Failed to generate self-signed certificate")
		return ctrl.Result{}, nil
	}
	// Create the secret object
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certificate.Spec.SecretRef.Name,
			Namespace: certificate.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte(cert),
			corev1.TLSPrivateKeyKey: []byte(privKey),
		},
	}

	if certNotFoundError != nil {
		// certificate not found
		if secretNotFoundError != nil {
			// secret not found
			log.Log.Info("Certificate was deleted, skipping reconciliation")
		} else {
			// secret found for delete
			if err := r.Delete(ctx, &foundSecret); err != nil {
				log.Log.Error(err, "Certificate was delete but related secret could be deleted")
			} else {
				log.Log.Info("Certificate was deleted, secret has been deleted!")
			}
		}
		return ctrl.Result{}, nil
	} else {
		// certificate found
		if secretNotFoundError != nil {
			// secret not found, create it
			log.Log.Info("Creating new secret")
			if err := r.Create(ctx, secret); err != nil {
				log.Log.Error(err, "Unable to create secret")
			} else {
				log.Log.Info("Secret Created!")
			}
		} else {
			// secret found, update it
			log.Log.Info("Updating secret")
			if err := r.Update(ctx, secret); err != nil {
				log.Log.Error(err, "Unable to update secret")
			} else {
				log.Log.Info("Secret Updated!")
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certscontrollerkuberasticcomv1.Certificate{}).
		Complete(r)
}
