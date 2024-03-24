package twitter

type guestTokenResponse struct {
	GuestToken string `json:"guest_token,omitempty"`
}

type commonResponse struct {
	Errors []twitterError `json:"errors,omitempty"`
}

type onboardingResponse struct {
	*commonResponse
	FlowToken string `json:"flow_token,omitempty"`
}

type twitterError struct {
	Message string `json:"message,omitempty"`
	Code    int64  `json:"code,omitempty"`
}

type onboardingRequest struct {
	FlowToken     string          `json:"flow_token,omitempty"`
	SubtaskInputs []*subtaskInput `json:"subtask_inputs,omitempty"`
}

type authorizeRequest struct {
	Approval string `json:"approval,omitempty"`
	Code     string `json:"code,omitempty"`
}

type authorizeResponse struct {
	*commonResponse
}

type subtaskInput struct {
	SubtaskId            string                `json:"subtask_id,omitempty"`
	SettingsList         *settingsList         `json:"settings_list,omitempty"`
	EnterPassword        *enterPassword        `json:"enter_password,omitempty"`
	CheckLoggedInAccount *checkLoggedInAccount `json:"check_logged_in_account,omitempty"`
	EnterText            *enterText            `json:"enter_text,omitempty"`
	JsInstrumentation    *jsInstrumentation    `json:"js_instrumentation,omitempty"`
}

type jsInstrumentation struct {
	Response string `json:"response,omitempty"`
	Link     string `json:"link,omitempty"`
}

type enterText struct {
	Text string `json:"text,omitempty"`
	Link string `json:"link,omitempty"`
}

type checkLoggedInAccount struct {
	Link string `json:"link,omitempty"`
}

type enterPassword struct {
	Password string `json:"password,omitempty"`
	Link     string `json:"link,omitempty"`
}

type settingsList struct {
	SettingResponses []*settingResponse `json:"setting_responses,omitempty"`
	Link             string             `json:"link,omitempty"`
}

type settingResponse struct {
	Key          string        `json:"key,omitempty"`
	ResponseData *responseData `json:"response_data,omitempty"`
}

type responseData struct {
	TextData *textData `json:"text_data,omitempty"`
}

type textData struct {
	Result string `json:"result,omitempty"`
}
