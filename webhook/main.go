package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	admissionv1 "k8s.io/api/admission/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	// Runtime scheme and codec factory needed for decoding Kubernetes objects
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

const (
	// Name of the NetworkPolicy that should not be deleted
	protectedNetworkPolicyName = "denyall"
)

func init() {
	// Add known types to the scheme
	// This ensures the deserializer knows how to handle AdmissionReview and NetworkPolicy objects
	_ = admissionv1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
}

// AdmissionResponse creates a basic AdmissionResponse structure.
// It sets Allowed to the provided boolean and includes a message if one is given.
func AdmissionResponse(allowed bool, message string) *admissionv1.AdmissionResponse {
	response := &admissionv1.AdmissionResponse{
		Allowed: allowed,
	}
	// If a message is provided, wrap it in a metav1.Status object
	if message != "" {
		response.Result = &metav1.Status{
			Message: message,
		}
	}
	return response
}

// handleValidate is the main HTTP handler function for the /validate endpoint.
// It processes incoming AdmissionReview requests.
func handleValidate(w http.ResponseWriter, r *http.Request) {
	log.Println("Received validation request")

	// Read the entire request body
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close() // Ensure the body is closed after reading
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Could not read request body", http.StatusBadRequest)
		return
	}

	// Decode the JSON request body into an AdmissionReview object
	// Uses the universal deserializer created from the scheme
	deserializer := codecs.UniversalDeserializer()
	admissionReview := &admissionv1.AdmissionReview{}
	_, _, err = deserializer.Decode(body, nil, admissionReview)
	if err != nil {
		log.Printf("Error decoding admission review: %v", err)
		http.Error(w, "Could not decode admission review", http.StatusBadRequest)
		return
	}

	// The AdmissionReview might be empty if decoding failed or the request was malformed
	if admissionReview.Request == nil {
		log.Println("AdmissionReview request is nil")
		http.Error(w, "AdmissionReview request is nil", http.StatusBadRequest)
		return
	}

	// --- Start Validation Logic ---

	// Default response: Allow the request unless specific conditions are met
	response := AdmissionResponse(true, "")

	// Check if the request is a DELETE operation for a NetworkPolicy resource
	// Uses constants from the networkingv1 API group
	if admissionReview.Request.Operation == admissionv1.Delete &&
		admissionReview.Request.Kind.Kind == "NetworkPolicy" &&
		admissionReview.Request.Kind.Group == networkingv1.SchemeGroupVersion.Group &&
		admissionReview.Request.Kind.Version == networkingv1.SchemeGroupVersion.Version {

		// Log details about the specific request being processed
		log.Printf("Processing DELETE request for NetworkPolicy '%s' in namespace '%s'", admissionReview.Request.Name, admissionReview.Request.Namespace)

		// Check if the name of the NetworkPolicy being deleted matches the protected name
		if admissionReview.Request.Name == protectedNetworkPolicyName {
			// If it matches, create a denial message and set the response to deny
			denialMessage := fmt.Sprintf("Deleting the NetworkPolicy named '%s' is not allowed by policy.", protectedNetworkPolicyName)
			log.Println(denialMessage)
			response = AdmissionResponse(false, denialMessage) // Deny the request
		} else {
			// If the name doesn't match, log that it's allowed (implicitly, as the default is allow)
			log.Printf("Allowing deletion of NetworkPolicy '%s' (doesn't match protected name '%s')", admissionReview.Request.Name, protectedNetworkPolicyName)
		}
	} else {
		// Log requests that don't match the criteria (e.g., different operation, different resource type)
		// This helps in debugging to see what requests the webhook is receiving
		log.Printf("Ignoring request: Operation=%s, Kind=%s/%s, Name=%s",
			admissionReview.Request.Operation,
			admissionReview.Request.Kind.Group, admissionReview.Request.Kind.Kind,
			admissionReview.Request.Name)
	}
	// --- End Validation Logic ---

	// Set the response field in the AdmissionReview object
	admissionReview.Response = response
	// Crucially, the response UID must match the request UID
	if admissionReview.Request != nil {
		admissionReview.Response.UID = admissionReview.Request.UID
	}

	// Marshal the AdmissionReview object (containing the response) back into JSON
	respBytes, err := json.Marshal(admissionReview)
	if err != nil {
		log.Printf("Error marshalling response: %v", err)
		http.Error(w, "Could not marshal response", http.StatusInternalServerError)
		return
	}

	// Send the JSON response back to the Kubernetes API server
	w.Header().Set("Content-Type", "application/json")
	// Admission webhooks always return HTTP 200 OK.
	// The actual decision (allow/deny) is inside the JSON payload (AdmissionReview.Response.Allowed).
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(respBytes)
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
	log.Println("Finished processing validation request")
}

// main is the entry point of the application
func main() {
	// Retrieve TLS certificate and key file paths from environment variables.
	// Provide default paths often used when mounting secrets in Kubernetes.
	certFile := os.Getenv("TLS_CERT_FILE")
	if certFile == "" {
		certFile = "/etc/webhook/certs/tls.crt"
	}
	keyFile := os.Getenv("TLS_KEY_FILE")
	if keyFile == "" {
		keyFile = "/etc/webhook/certs/tls.key"
	}

	log.Printf("Starting webhook server on port 8443...")
	log.Printf("Using cert file: %s", certFile)
	log.Printf("Using key file: %s", keyFile)

	// Basic check to ensure the certificate and key files actually exist at the specified paths.
	// The server will fail to start if they are missing.
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Fatalf("TLS certificate file not found: %s", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatalf("TLS key file not found: %s", keyFile)
	}

	// Create a new HTTP request multiplexer (router)
	mux := http.NewServeMux()
	// Register the handleValidate function for the "/validate" path
	mux.HandleFunc("/validate", handleValidate)

	// Configure the HTTPS server
	server := &http.Server{
		Addr:    ":8443", // Listen on port 8443
		Handler: mux,     // Use the configured router
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, // Enforce minimum TLS version for security
			// Consider adding CipherSuites preference if needed
		},
	}

	// Start the HTTPS server. ListenAndServeTLS blocks until the server stops.
	// It requires the paths to the certificate and key files.
	// log.Fatal will print the error and exit if the server fails to start (e.g., port conflict, cert issues).
	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}