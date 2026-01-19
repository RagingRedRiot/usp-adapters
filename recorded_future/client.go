package usp_recordedfuture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/refractionPOINT/go-uspclient"
	"github.com/refractionPOINT/go-uspclient/protocol"
	"github.com/refractionPOINT/usp-adapters/utils"
)

const (
	queryInterval        = 60
	triggeredAlertsPath  = "/alert/v3"
	playbookAlertsPath   = "/playbook-alert/search"
)

type RecordedFutureConfig struct {
	ClientOptions       uspclient.ClientOptions `json:"client_options" yaml:"client_options"`
	Url                 string                  `json:"url" yaml:"url"`
	ApiToken            string                  `json:"api_token" yaml:"api_token"`
	InitialLookback     time.Duration           `json:"initial_lookback,omitempty" yaml:"initial_lookback,omitempty"`
}

type RecordedFutureAdapter struct {
	conf                    RecordedFutureConfig
	uspClient               *uspclient.Client
	httpClient              *http.Client
	chStopped               chan struct{}

	once                    sync.Once
	ctx                     context.Context
	cancel                  context.CancelFunc

	triggeredAlertDedupe    map[string]int64
	playbookAlertDedupe     map[string]int64
}

type RecordedFutureResponse interface {
	GetDict() []utils.Dict
}

// For triggered alerts (v3 API)
type TriggeredAlertsResponse struct {
	Data []utils.Dict `json:"data"`
}

func (r *TriggeredAlertsResponse) GetDict() []utils.Dict {
	return r.Data
}

// For playbook alerts (search API)
type PlaybookAlertsResponse struct {
	Data struct {
		Results []utils.Dict `json:"results"`
	} `json:"data"`
}

func (r *PlaybookAlertsResponse) GetDict() []utils.Dict {
	return r.Data.Results
}

func NewRecordedFutureAdapter(ctx context.Context, conf RecordedFutureConfig) (*RecordedFutureAdapter, chan struct{}, error) {
	if err := conf.Validate(); err != nil {
		return nil, nil, err
	}
	a := &RecordedFutureAdapter{
		conf:                 conf,
		triggeredAlertDedupe: make(map[string]int64),
		playbookAlertDedupe:  make(map[string]int64),
	}

	rootCtx, cancel := context.WithCancel(ctx)
	a.ctx = rootCtx
	a.cancel = cancel

	var err error
	a.uspClient, err = uspclient.NewClient(rootCtx, conf.ClientOptions)
	if err != nil {
		return nil, nil, err
	}

	a.httpClient = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	a.chStopped = make(chan struct{})

	go a.fetchEvents()

	return a, a.chStopped, nil
}

func (c *RecordedFutureConfig) Validate() error {
	if err := c.ClientOptions.Validate(); err != nil {
		return fmt.Errorf("client_options: %v", err)
	}
	if c.Url == "" {
		return errors.New("missing url")
	}
	if c.ApiToken == "" {
		return errors.New("missing api_token")
	}
	// InitialLookback defaults to zero (current time, no lookback)
	return nil
}

func (a *RecordedFutureAdapter) Close() error {
	a.conf.ClientOptions.DebugLog("closing")
	var err1, err2 error
	a.once.Do(func() {
		a.cancel()
		err1 = a.uspClient.Drain(1 * time.Minute)
		_, err2 = a.uspClient.Close()
		a.httpClient.CloseIdleConnections()
		close(a.chStopped)
	})
	if err1 != nil {
		return err1
	}
	return err2
}

type API struct {
	Endpoint     string
	Key          string
	ResponseType RecordedFutureResponse
	Dedupe       map[string]int64
	timeField    string
}

func (a *RecordedFutureAdapter) fetchEvents() {
	since := map[string]time.Time{
		"triggeredAlerts": time.Now().Add(-1 * a.conf.InitialLookback).UTC(),
		"playbookAlerts":  time.Now().Add(-1 * a.conf.InitialLookback).UTC(),
	}

	APIs := []API{
		{
			Endpoint:     triggeredAlertsPath,
			Key:          "triggeredAlerts",
			ResponseType: &TriggeredAlertsResponse{},
			timeField:    "triggered",
			Dedupe:       a.triggeredAlertDedupe,
		},
		{
			Endpoint:     playbookAlertsPath,
			Key:          "playbookAlerts",
			ResponseType: &PlaybookAlertsResponse{},
			timeField:    "created",
			Dedupe:       a.playbookAlertDedupe,
		},
	}

	ticker := time.NewTicker(queryInterval * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.conf.ClientOptions.DebugLog(fmt.Sprintf("fetching of %s events exiting", a.conf.Url))
			return
		case <-ticker.C:
			// Capture current time once for all APIs in this cycle
			cycleTime := time.Now()

			allItems := []utils.Dict{}

			for _, api := range APIs {
				items, err := a.getEvents(since[api.Key], cycleTime, api)
				if err != nil {
					a.conf.ClientOptions.OnError(fmt.Errorf("%s fetch failed: %w", api.Key, err))
					continue
				}

				if len(items) > 0 {
					since[api.Key] = cycleTime.Add(-queryInterval * time.Second)
					allItems = append(allItems, items...)
				}
			}

			if len(allItems) > 0 {
				a.submitEvents(allItems)
			}
		}
	}
}

func (a *RecordedFutureAdapter) getEvents(since time.Time, cycleTime time.Time, api API) ([]utils.Dict, error) {
	var allItems []utils.Dict

	// Cull old dedupe entries - keep entries from the last lookback period
	// to handle duplicates during the overlap window
	cutoffTime := cycleTime.Add(-2 * queryInterval * time.Second).Unix()
	for k, v := range api.Dedupe {
		if v < cutoffTime {
			delete(api.Dedupe, k)
		}
	}

	response, err := a.doRequest(since, cycleTime, api)
	if err != nil {
		return nil, err
	}

	for _, event := range response.GetDict() {
		// Generate hash-based ID for deduplication
		dedupeID := a.generateLogHash(event)

		// Get timestamp - handle both string and numeric formats
		var timeString time.Time
		timeValue, exists := event[api.timeField]
		if !exists {
			a.conf.ClientOptions.OnWarning(fmt.Sprintf("%s: event missing time field '%s'", api.Key, api.timeField))
			continue
		}

		switch v := timeValue.(type) {
		case string:
			// Parse ISO 8601 timestamp
			timeString, err = time.Parse(time.RFC3339, v)
			if err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("recorded_future %s api invalid string timestamp: %v\n%v", api.Key, err, event))
				continue
			}
		case float64:
			// Handle numeric timestamp (milliseconds)
			timeString = time.UnixMilli(int64(v))
		case int64:
			timeString = time.UnixMilli(v)
		case uint64:
			timeString = time.UnixMilli(int64(v))
		case int:
			timeString = time.UnixMilli(int64(v))
		default:
			a.conf.ClientOptions.OnWarning(fmt.Sprintf("%s: event time field '%s' has unsupported type %T with value: %v", api.Key, api.timeField, timeValue, timeValue))
			continue
		}

		// Check for duplicates using hash-based ID
		if _, seen := api.Dedupe[dedupeID]; !seen {
			if timeString.After(since) || timeString.Equal(since) {
				// Store the event timestamp for dedupe cleanup
				api.Dedupe[dedupeID] = timeString.Unix()
				allItems = append(allItems, event)
			}
		}
	}

	return allItems, nil
}

func (a *RecordedFutureAdapter) generateLogHash(logMap map[string]interface{}) string {
	// Extract and sort keys
	keys := make([]string, 0, len(logMap))
	for k := range logMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build deterministic string representation
	var buf bytes.Buffer
	for _, k := range keys {
		fmt.Fprintf(&buf, "%s:%v|", k, logMap[k])
	}

	hash := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(hash[:])
}

func (a *RecordedFutureAdapter) doRequest(since time.Time, cycleTime time.Time, api API) (RecordedFutureResponse, error) {
	for {
		select {
		case <-a.ctx.Done():
			return nil, a.ctx.Err()
		default:
		}

		var respBody []byte
		var status int

		err := func() error {
			loopCtx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
			defer cancel()

			// Build URL and request body based on API type
			url := fmt.Sprintf("%s%s", a.conf.Url, api.Endpoint)
			var reqBody []byte
			var method string
			var err error

			if api.Key == "triggeredAlerts" {
				// For triggered alerts, use GET with query parameters
				method = "GET"
				url = fmt.Sprintf("%s?triggered_after=%s&limit=1000", url, since.Format(time.RFC3339))
			} else {
				// For playbook alerts, use POST with JSON body
				method = "POST"
				body := map[string]interface{}{
					"from":  0,
					"limit": 1000,
					"order_by": []map[string]string{
						{"created": "desc"},
					},
					"filters": []map[string]interface{}{
						{
							"path":     "created",
							"operator": "gte",
							"value":    since.Format(time.RFC3339),
						},
						{
							"path":     "created",
							"operator": "lte",
							"value":    cycleTime.Format(time.RFC3339),
						},
					},
				}
				reqBody, err = json.Marshal(body)
				if err != nil {
					return err
				}
			}

			var req *http.Request
			if len(reqBody) > 0 {
				req, err = http.NewRequestWithContext(loopCtx, method, url, bytes.NewReader(reqBody))
			} else {
				req, err = http.NewRequestWithContext(loopCtx, method, url, nil)
			}
			if err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("recorded_future %s api request error: %v", api.Key, err))
				return err
			}

			req.Header.Set("X-RFToken", a.conf.ApiToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := a.httpClient.Do(req)
			if err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("recorded_future %s api do error: %v", api.Key, err))
				return err
			}
			defer resp.Body.Close()

			respBody, err = io.ReadAll(resp.Body)
			if err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("recorded_future %s api read error: %v", api.Key, err))
				return err
			}
			status = resp.StatusCode
			return nil
		}()

		if err != nil {
			return nil, err
		}

		if status == http.StatusTooManyRequests {
			a.conf.ClientOptions.OnWarning("getEventsRequest got 429, sleeping 60s before retry")
			if err := a.sleepContext(60 * time.Second); err != nil {
				return nil, err
			}
			continue
		}

		if status != http.StatusOK {
			return nil, fmt.Errorf("recorded_future %s api non-200: %d\nRESPONSE %s", api.Key, status, string(respBody))
		}

		err = json.Unmarshal(respBody, api.ResponseType)
		if err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("recorded_future %s api invalid json: %v\nResponse body: %s", api.Key, err, string(respBody)))
			return nil, err
		}

		return api.ResponseType, nil
	}
}

func (a *RecordedFutureAdapter) submitEvents(items []utils.Dict) {
	for _, item := range items {
		msg := &protocol.DataMessage{
			JsonPayload: item,
			TimestampMs: uint64(time.Now().UTC().UnixNano() / int64(time.Millisecond)),
		}
		if err := a.uspClient.Ship(msg, 10*time.Second); err != nil {
			if err == uspclient.ErrorBufferFull {
				a.conf.ClientOptions.OnWarning("stream falling behind")
				if err := a.uspClient.Ship(msg, 1*time.Hour); err != nil {
					a.conf.ClientOptions.OnError(fmt.Errorf("Ship(): %v", err))
					a.Close()
					return
				}
			} else {
				a.conf.ClientOptions.OnError(fmt.Errorf("Ship(): %v", err))
			}
		}
	}
}

func (a *RecordedFutureAdapter) sleepContext(d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-a.ctx.Done():
		return a.ctx.Err()
	}
}