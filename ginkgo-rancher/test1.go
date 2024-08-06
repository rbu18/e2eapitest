package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// LoginPayload represents the JSON structure for login request payload
type LoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the JSON structure of the login response
type LoginResponse struct {
	Token string `json:"token"`
}

func TestRancherLogin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rancher Login Suite")
}

var (
	rancherURL string
	username   string
	password   string
	token      string
	client     *http.Client
)

var _ = BeforeSuite(func() {
	rancherURL = "https://172.17.0.2"
	username = "admin"
	password = "R@nchersuse2024"

	// Create a custom HTTP client that ignores SSL certificate verification
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
})

var _ = Describe("Rancher Login", func() {
	It("should return a valid token upon successful login", func() {
		// Create login payload
		payload := LoginPayload{
			Username: username,
			Password: password,
		}

		// Serialize payload to JSON
		payloadBytes, err := json.Marshal(payload)
		Expect(err).NotTo(HaveOccurred(), "Failed to marshal login payload")

		// Define the API endpoint for login
		loginEndpoint := fmt.Sprintf("%s/v3-public/localProviders/local?action=login", rancherURL)

		// Create a new POST request
		req, err := http.NewRequest("POST", loginEndpoint, bytes.NewBuffer(payloadBytes))
		Expect(err).NotTo(HaveOccurred(), "Failed to create POST request")

		req.Header.Set("Content-Type", "application/json")

		// Perform the POST request using the custom client
		resp, err := client.Do(req)
		Expect(err).NotTo(HaveOccurred(), "Failed to perform POST request")
		defer resp.Body.Close()

		// Check if login was successful
		Expect(resp.StatusCode).To(Equal(http.StatusCreated), "Login failed")

		// Read and parse response body
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		Expect(err).NotTo(HaveOccurred(), "Failed to read response body")

		var loginResponse LoginResponse
		err = json.Unmarshal(bodyBytes, &loginResponse)
		Expect(err).NotTo(HaveOccurred(), "Failed to unmarshal response")

		Expect(loginResponse.Token).ToNot(BeEmpty(), "Token should not be empty")
		token = loginResponse.Token
	})
})

var _ = AfterSuite(func() {
	// Clean up or log the token if necessary
	if token != "" {
		fmt.Printf("Received token: %s\n", token)
	}
})
