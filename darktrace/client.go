package usp_darktrace

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/refractionPOINT/go-uspclient"
	"github.com/refractionPOINT/go-uspclient/protocol"
	"github.com/refractionPOINT/usp-adapters/utils"
)

const (
	queryInterval     = 60
	aiAnalystAlerts   = "/aianalyst/incidentevents?includeacknowledged=true&includeincidenteventurl=true"
	modelBreachAlerts = "/modelbreaches?expandenums=true&historicmodelonly=true&includeacknowledged=true&includebreachurl=true"
)

type DarktraceConfig struct {
	ClientOptions uspclient.ClientOptions `json:"client_options" yaml:"client_options"`
	Url           string                  `json:"url" yaml:"url"`
	PublicToken   string                  `json:"public_token" yaml:"public_token"`
	PrivateToken  string                  `json:"private_token" yaml:"private_token"`
}

type DarkTraceAdapter struct {
	conf       DarktraceConfig
	uspClient  *uspclient.Client
	httpClient *http.Client
	chStopped  chan struct{}

	once   sync.Once
	ctx    context.Context
	cancel context.CancelFunc

	aiAnalystDedupe   map[string]int64
	modelBreachDedupe map[string]int64
}

type DarktraceResponse interface {
	GetDict() []utils.Dict
}

type DarktraceEventsResponse []utils.Dict

func (r DarktraceEventsResponse) GetDict() []utils.Dict {
	return []utils.Dict(r)
}

func NewDarkTraceAdapter(conf DarktraceConfig) (*DarkTraceAdapter, chan struct{}, error) {
	if err := conf.Validate(); err != nil {
		return nil, nil, err
	}
	a := &DarkTraceAdapter{
		conf:              conf,
		aiAnalystDedupe:   make(map[string]int64),
		modelBreachDedupe: make(map[string]int64),
	}

	rootCtx, cancel := context.WithCancel(context.Background())
	a.ctx = rootCtx
	a.cancel = cancel

	var err error
	a.uspClient, err = uspclient.NewClient(conf.ClientOptions)
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

func (c *DarktraceConfig) Validate() error {
	if err := c.ClientOptions.Validate(); err != nil {
		return fmt.Errorf("client_options: %v", err)
	}
	if c.Url == "" {
		return errors.New("missing url")
	}
	if c.PublicToken == "" {
		return errors.New("missing public token")
	}
	if c.PrivateToken == "" {
		return errors.New("missing private token")
	}
	return nil
}

func (a *DarkTraceAdapter) Close() error {
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
	ResponseType DarktraceResponse
	Dedupe       map[string]int64
	idField      string
	timeField    string
	timeFormat   string
}

func (a *DarkTraceAdapter) fetchEvents() {

	since := map[string]int64{
		"aiAnalyst":     time.Now().UTC().UnixMilli(),
		"modelBreaches": time.Now().UTC().UnixMilli(),
	}

	APIs := []API{
		{
			Endpoint:     aiAnalystAlerts,
			Key:          "aiAnalyst",
			ResponseType: &DarktraceEventsResponse{},
			timeFormat:   "20060102T150405",
			idField:      "id",
			timeField:    "detectiontime",
			Dedupe:       a.aiAnalystDedupe,
		},
		{
			Endpoint:     modelBreachAlerts,
			Key:          "modelBreaches",
			ResponseType: &DarktraceEventsResponse{},
			timeFormat:   "20060102T150405",
			idField:      "id",
			timeField:    "detectiontime",
			Dedupe:       a.modelBreachDedupe,
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

			allItems := []utils.Dict{}

			for _, api := range APIs {
				pageURL := fmt.Sprintf("%s%s", a.conf.Url, api.Endpoint)
				items, newSince, err := a.getEvents(pageURL, since[api.Key], api)
				if err != nil {
					a.conf.ClientOptions.OnError(fmt.Errorf("%s fetch failed: %w", api.Key, err))
					continue
				}
				since[api.Key] = newSince
				allItems = append(allItems, items...)
			}

			if len(allItems) > 0 {
				a.submitEvents(allItems)
			}
		}
	}
}

func (a *DarkTraceAdapter) getEvents(pageUrl string, since int64, api API) ([]utils.Dict, int64, error) {
	var allItems []utils.Dict
	lastDetectionTime := since

	defer func() {
		for k, v := range api.Dedupe {
			if v < time.UnixMilli(since).Add(-1*time.Minute).UnixMilli() {
				delete(api.Dedupe, k)
			}
		}
	}()

	urlWithTimes := fmt.Sprintf("%s&starttime=%d&endtime=%d", pageUrl, since, time.Now().UTC().UnixMilli())

	response, err := a.doWithRetry(urlWithTimes, api)
	if err != nil {
		return nil, 0, err
	}

	for _, event := range response.GetDict() {
		id, ok := event[api.idField].(string)
		if !ok {
			a.conf.ClientOptions.OnWarning(fmt.Sprintf("event id not a string: %s", event))
			continue
		}
		timeStr, ok := event[api.timeField].(string)
		if !ok {
			a.conf.ClientOptions.OnWarning(fmt.Sprintf("event time not a string: %s", event))
			continue
		}

		if _, seen := api.Dedupe[id]; !seen {
			timeString, err := time.Parse(api.timeFormat, timeStr)
			if err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("darktrace %s api invalid timestamp: %v\n%v", api.Key, err, event))
				continue
			}
			if timeString.After(time.UnixMilli(since)) {
				api.Dedupe[id] = time.Now().UTC().UnixMilli()
				allItems = append(allItems, event)
				if timeString.After(time.UnixMilli(lastDetectionTime)) {
					lastDetectionTime = timeString.UnixMilli()
				}
			}
		}
	}
	return allItems, lastDetectionTime, nil
}

func (a *DarkTraceAdapter) generateSignature(timeString string, fullURL string) (string, error) {
	u, err := url.Parse(fullURL)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha1.New, []byte(a.conf.PrivateToken))
	payload := fmt.Sprintf("%s\n%s\n%s", u.RequestURI(), a.conf.PublicToken, timeString)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (a *DarkTraceAdapter) doWithRetry(url string, api API) (DarktraceResponse, error) {
	for {
		var respBody []byte
		var status int

		err := func() error {
			loopCtx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(loopCtx, "GET", url, nil)
			if err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("darktrace %s api request error: %v", api.Key, err))
				return err
			}

			nowTime := time.Now().UTC().Format(api.timeFormat)

			signature, err := a.generateSignature(nowTime, url)
			if err != nil {
				return err
			}

			req.Header.Set("DTAPI-Token", a.conf.PublicToken)
			req.Header.Set("DTAPI-Date", nowTime)
			req.Header.Set("DTAPI-Signature", signature)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := a.httpClient.Do(req)
			if err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("darktrace %s api do error: %v", api.Key, err))
				return err
			}

			defer resp.Body.Close()

			respBody, err = io.ReadAll(resp.Body)
			if err != nil {
				a.conf.ClientOptions.OnError(fmt.Errorf("darktrace %s api read error: %v", api.Key, err))
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
			a.conf.ClientOptions.OnError(fmt.Errorf("darktrace %s api non-200: %d\nRESPONSE %s", api.Key, status, string(respBody)))
			return nil, fmt.Errorf("darktrace %s api non-200: %d\nRESPONSE %s", api.Key, status, string(respBody))
		}

		err = json.Unmarshal(respBody, &api.ResponseType)
		if err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("darktrace %s api invalid json: %v", api.Key, err))
			return nil, err
		}

		return api.ResponseType, nil
	}
}

func (a *DarkTraceAdapter) submitEvents(items []utils.Dict) {
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
			}
		}
	}
}

func (a *DarkTraceAdapter) sleepContext(d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-a.ctx.Done():
		return a.ctx.Err()
	}
}
