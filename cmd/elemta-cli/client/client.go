package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client represents an API client for Elemta
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// Message represents an email message in the queue
type Message struct {
	ID        string   `json:"id"`
	QueueType string   `json:"queueType"`
	FilePath  string   `json:"filePath"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	Subject   string   `json:"subject"`
	Size      int64    `json:"size"`
	Content   string   `json:"content,omitempty"`
}

// QueueStats represents statistics about the queues
type QueueStats map[string]int

// NewClient creates a new API client
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// queueListEnvelope mirrors the server's paged listing response. The listing
// endpoints stopped returning bare arrays when pagination was added; Total
// reports how many messages matched beyond the returned page.
type queueListEnvelope struct {
	Messages []Message `json:"messages"`
	Total    int       `json:"total"`
}

// cliQueuePageSize asks for the server's maximum page. The CLI prints a table,
// and past a few hundred rows more data helps nobody at a terminal — the
// count line reports the rest.
const cliQueuePageSize = 500

// GetAllMessages returns the newest messages across all queues, and the total
// count of messages beyond the returned page.
func (c *Client) GetAllMessages() ([]Message, int, error) {
	var envelope queueListEnvelope
	err := c.get(fmt.Sprintf("/api/queue?limit=%d", cliQueuePageSize), &envelope)
	return envelope.Messages, envelope.Total, err
}

// GetQueueMessages returns the newest messages in a specific queue, and the
// total count of messages beyond the returned page.
func (c *Client) GetQueueMessages(queueType string) ([]Message, int, error) {
	var envelope queueListEnvelope
	err := c.get(fmt.Sprintf("/api/queue/%s?limit=%d", queueType, cliQueuePageSize), &envelope)
	return envelope.Messages, envelope.Total, err
}

// GetMessage returns a specific message
func (c *Client) GetMessage(id string) (*Message, error) {
	var message Message
	err := c.get(fmt.Sprintf("/api/queue/message/%s", id), &message)
	return &message, err
}

// GetMessageRaw returns the raw content of a specific message
func (c *Client) GetMessageRaw(id string) (string, error) {
	resp, err := c.doRequest("GET", fmt.Sprintf("/api/queue/message/%s?format=raw", id), nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }() // Ignore error in defer cleanup

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// DeleteMessage deletes a specific message
func (c *Client) DeleteMessage(id string) error {
	_, err := c.doRequest("DELETE", fmt.Sprintf("/api/queue/message/%s", id), nil)
	return err
}

// FlushQueue flushes a specific queue
func (c *Client) FlushQueue(queueType string) error {
	_, err := c.doRequest("POST", fmt.Sprintf("/api/queue/%s/flush", queueType), nil)
	return err
}

// FlushAllQueues flushes all queues
func (c *Client) FlushAllQueues() error {
	return c.FlushQueue("all")
}

// GetQueueStats returns statistics about the queues
func (c *Client) GetQueueStats() (QueueStats, error) {
	var stats QueueStats
	err := c.get("/api/queue/stats", &stats)
	return stats, err
}

// Helper functions

// get performs a GET request and unmarshals the response
func (c *Client) get(path string, result interface{}) error {
	resp, err := c.doRequest("GET", path, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // Ignore error in defer cleanup

	return json.NewDecoder(resp.Body).Decode(result)
}

// doRequest performs an HTTP request
func (c *Client) doRequest(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	url := c.baseURL + path
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		defer func() { _ = resp.Body.Close() }() // Ignore error in defer cleanup
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s (status code %d)", string(body), resp.StatusCode)
	}

	return resp, nil
}
