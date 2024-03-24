package twitter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/corpix/uarand"
	"github.com/dgryski/dgoogauth"
	"go.uber.org/zap"
)

type Twitter struct {
	logger *zap.Logger

	cookies   string
	proxy     string
	userAgent string
}

func NewTwitter() *Twitter {
	logger, _ := zap.NewProduction()
	return &Twitter{
		logger:    logger,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
	}
}

func (t *Twitter) Login(username string, password string, secret string) (cookie string, err error) {
	var guestToken string
	guestToken, err = t.GetGuestToken()
	if err != nil {
		t.logger.Error("Failed to get guest token", zap.Error(err))
		return
	}

	onboardingTaskUrl := "https://twitter.com/i/api/1.1/onboarding/task.json"
	// flow 1: start flow login
	onboardingReq := &onboardingRequest{}
	var body []byte
	req, _ := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s?flow_name=login", onboardingTaskUrl),
		nil)
	req.Header.Add("referer", "https://twitter.com/sw.js")
	req.Header.Add("x-guest-token", guestToken)

	var data *http.Response
	data, err = t.makeRequest(req)
	if err != nil {
		t.logger.Error("Failed to make request", zap.Error(err))
		return
	}

	var att string
	cookies := data.Header["Set-Cookie"]
	for _, cookie := range cookies {
		if strings.HasPrefix(cookie, "att=") {
			att = strings.Split(cookie, ";")[0]
			att = strings.TrimPrefix(att, "att=")
			break
		}
	}
	var resp onboardingResponse
	err = decodeResponseBody(data, &resp)
	if err != nil {
		t.logger.Error("Failed to decode response body", zap.Error(err))
		return
	}

	if len(resp.Errors) > 0 {
		t.logger.Error("Failed to login", zap.Any("errors", resp.Errors))
		return
	}

	// flow 2: LoginJsInstrumentationSubtask
	onboardingReq = &onboardingRequest{
		FlowToken: resp.FlowToken,
		SubtaskInputs: []*subtaskInput{
			{
				SubtaskId: "LoginJsInstrumentationSubtask",
				JsInstrumentation: &jsInstrumentation{
					Response: "{}",
					Link:     "next_link",
				},
			},
		},
	}

	body, _ = json.Marshal(onboardingReq)
	req, _ = http.NewRequest(
		http.MethodPost,
		onboardingTaskUrl,
		bytes.NewBuffer(body))
	req.Header.Add("referer", "https://twitter.com/sw.js")
	req.Header.Add("att", att)
	req.Header.Add("x-guest-token", guestToken)

	data, err = t.makeRequest(req)
	if err != nil {
		t.logger.Error("Failed to make request", zap.Error(err))
		return
	}
	err = decodeResponseBody(data, &resp)
	if err != nil {
		t.logger.Error("Failed to decode response body", zap.Error(err))
		return
	}

	if len(resp.Errors) > 0 {
		t.logger.Error("Failed to login", zap.Any("errors", resp.Errors))
		return
	}

	// flow 3: enter username
	onboardingReq = &onboardingRequest{
		FlowToken: resp.FlowToken,
		SubtaskInputs: []*subtaskInput{
			{
				SubtaskId: "LoginEnterUserIdentifierSSO",
				SettingsList: &settingsList{
					SettingResponses: []*settingResponse{
						{
							Key: "user_identifier",
							ResponseData: &responseData{
								TextData: &textData{
									Result: username,
								},
							},
						},
					},
					Link: "next_link",
				},
			},
		},
	}
	body, _ = json.Marshal(onboardingReq)
	req, _ = http.NewRequest(
		http.MethodPost,
		onboardingTaskUrl,
		bytes.NewBuffer(body))
	req.Header.Add("referer", "https://twitter.com/sw.js")
	req.Header.Add("att", att)
	req.Header.Add("x-guest-token", guestToken)

	data, err = t.makeRequest(req)
	if err != nil {
		t.logger.Error("Failed to make request", zap.Error(err))
		return
	}
	err = decodeResponseBody(data, &resp)
	if err != nil {
		t.logger.Error("Failed to decode response body", zap.Error(err))
		return
	}

	if len(resp.Errors) > 0 {
		t.logger.Error("Failed to login", zap.Any("errors", resp.Errors))
		return
	}

	// flow 4: enter password
	onboardingReq = &onboardingRequest{
		FlowToken: resp.FlowToken,
		SubtaskInputs: []*subtaskInput{
			{
				SubtaskId: "LoginEnterPassword",
				EnterPassword: &enterPassword{
					Password: password,
					Link:     "next_link",
				},
			},
		},
	}
	body, _ = json.Marshal(onboardingReq)
	req, _ = http.NewRequest(
		http.MethodPost,
		onboardingTaskUrl,
		bytes.NewBuffer(body))
	req.Header.Add("referer", "https://twitter.com/sw.js")
	req.Header.Add("att", att)
	req.Header.Add("x-guest-token", guestToken)

	data, err = t.makeRequest(req)
	if err != nil {
		t.logger.Error("Failed to make request", zap.Error(err))
		return
	}
	err = decodeResponseBody(data, &resp)
	if err != nil {
		t.logger.Error("Failed to decode response body", zap.Error(err))
		return
	}

	if len(resp.Errors) > 0 {
		t.logger.Error("Failed to login", zap.Any("errors", resp.Errors))
		return
	}

	// flow 5: AccountDuplicationCheck
	onboardingReq = &onboardingRequest{
		FlowToken: resp.FlowToken,
		SubtaskInputs: []*subtaskInput{
			{
				SubtaskId: "AccountDuplicationCheck",
				CheckLoggedInAccount: &checkLoggedInAccount{
					Link: "next_link",
				},
			},
		},
	}
	body, _ = json.Marshal(onboardingReq)
	req, _ = http.NewRequest(
		http.MethodPost,
		onboardingTaskUrl,
		bytes.NewBuffer(body))
	req.Header.Add("referer", "https://twitter.com/sw.js")
	req.Header.Add("att", att)
	req.Header.Add("x-guest-token", guestToken)

	data, err = t.makeRequest(req)
	if err != nil {
		t.logger.Error("Failed to make request", zap.Error(err))
		return
	}
	err = decodeResponseBody(data, &resp)
	if err != nil {
		t.logger.Error("Failed to decode response body", zap.Error(err))
		return
	}

	if len(resp.Errors) > 0 {
		t.logger.Error("Failed to login", zap.Any("errors", resp.Errors))
		return
	}

	// flow 6: LoginTwoFactorAuthChallenge
	code := dgoogauth.ComputeCode(secret, time.Now().Unix()/30)
	onboardingReq = &onboardingRequest{
		FlowToken: resp.FlowToken,
		SubtaskInputs: []*subtaskInput{
			{
				SubtaskId: "LoginTwoFactorAuthChallenge",
				EnterText: &enterText{
					Link: "next_link",
					Text: fmt.Sprintf("%06d", code),
				},
			},
		},
	}
	body, _ = json.Marshal(onboardingReq)
	req, _ = http.NewRequest(
		http.MethodPost,
		onboardingTaskUrl,
		bytes.NewBuffer(body))
	req.Header.Add("referer", "https://twitter.com/sw.js")
	req.Header.Add("att", att)
	req.Header.Add("x-guest-token", guestToken)

	data, err = t.makeRequest(req)
	if err != nil {
		t.logger.Error("Failed to make request", zap.Error(err))
		return
	}

	convertCookieToString := convertCookieToString(data.Header["Set-Cookie"])
	t.logger.Info("Login success", zap.Any("cookie", convertCookieToString))
	return convertCookieToString, nil
}

func (t *Twitter) Authorize(authCode string) (err error){
	authorizeReq := &authorizeRequest{
		Approval: "true",
		Code:     authCode,
	}

	body, _ := json.Marshal(authorizeReq)
	req, _ := http.NewRequest(http.MethodPost, "https://twitter.com/i/api/2/oauth2/authorize", bytes.NewBuffer(body))
	var response *http.Response
	response, err = t.makeRequest(req)
	if err != nil {
		t.logger.Error("Failed to make request", zap.Error(err))
		return
	}

	var resp authorizeResponse
	err = decodeResponseBody(response, &resp)
	if err != nil {
		t.logger.Error("Failed to decode response body", zap.Error(err))
		return
	}
	if len(resp.Errors) > 0 {
		t.logger.Error("Failed to authorize", zap.Any("errors", resp.Errors))
		return
	}
	t.logger.Info("Authorize success")
	return nil
}

func (t *Twitter) SetUserAgent(userAgent string) {
	t.userAgent = userAgent
}

func (t *Twitter) SetProxy(proxy string) {
	t.proxy = proxy
}

func (t *Twitter) SetCookies(cookies string) {
	t.cookies = cookies
}

func (t *Twitter) GetGuestToken() (string, error) {
	req, err := http.NewRequest(http.MethodPost, "https://api.twitter.com/1.1/guest/activate.json", nil)
	if err != nil {
		t.logger.Error("Failed to create request", zap.Error(err))
		return "", err
	}
	data, err := t.makeRequest(req)
	if err != nil {
		t.logger.Error("Failed to get guest token", zap.Error(err))
		return "", err
	}
	defer data.Body.Close()
	var resp guestTokenResponse
	err = decodeResponseBody(data, &resp)
	return resp.GuestToken, err
}

func (t *Twitter) makeRequest(req *http.Request) (*http.Response, error) {
	defaultHeaders := map[string]string{
		"authority":                 "twitter.com",
		"origin":                    "https://twitter.com",
		"x-twitter-active-user":     "yes",
		"x-twitter-client-language": "en",
		"content-type":              "application/json",
		"authorization":             "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
		"user-agent":                t.userAgent,
	}
	if len(t.cookies) > 0 {
		defaultHeaders["cookies"] = t.cookies
	}
	for key, value := range defaultHeaders {
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Add(key, value)
	}

	client := &http.Client{}

	if len(t.proxy) > 0 {
		proxyURL, err := url.Parse(t.proxy)
		if err != nil {
			t.logger.Error("Failed to parse proxy URL", zap.Error(err))
			return nil, err
		}
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		t.logger.Error("Failed to dump request", zap.Error(err))
		return nil, err
	}
	t.logger.Info("Request", zap.String("dump", string(dump)))

	resp, err := client.Do(req)
	if err != nil {
		t.logger.Error("Failed to make request", zap.Error(err))
		return nil, err
	}

	dump, err = httputil.DumpResponse(resp, true)
	if err != nil {
		t.logger.Error("Failed to dump response", zap.Error(err))
		return nil, err
	}
	t.logger.Info("Response", zap.String("dump", string(dump)))

	return resp, nil
}

func decodeResponseBody[T any](resp *http.Response, v *T) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(body, v)
	if err != nil {
		return err
	}

	return nil
}

func convertCookieToString(cookies []string) string {
	cookieData := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		// Split the cookie string on the ";" character to get the key-value pair
		parts := strings.Split(cookie, ";")
		// Only take the first part which is the actual key=value pair
		cookieData = append(cookieData, parts[0])
	}
	cookieString := strings.Join(cookieData, "; ")
	return cookieString
}
