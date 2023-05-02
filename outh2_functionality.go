package oauth2

import (
	"errors"
	"golang.org/x/oauth2"
	"io"
	"net/http"
)

type ConfigureOAuth2 struct {
	oauth2.Config
	State         string
	RequestMethod string
	Body          io.ReadCloser
	GetInfoURL    string
}

var (
	AuthorizationBearer = "Bearer"
	QueryString         = "query-string"
)

func Login(config *ConfigureOAuth2, opts ...oauth2.AuthCodeOption) string {
	return config.AuthCodeURL(config.State, opts...)
}

func CheckState(request *http.Request, state string) error {
	checkState := request.URL.Query()["state"][0]
	if checkState != state {
		return errors.New("invalid state")
	}
	return nil
}

func GetCode(request *http.Request) string {
	return request.URL.Query()["code"][0]
}

func GetToken(request *http.Request, config *oauth2.Config, code string) (*oauth2.Token, error) {
	return config.Exchange(request.Context(), code)
}

func Callback(request *http.Request, config *ConfigureOAuth2, sendThrough string) ([]byte, error) {
	stateError := CheckState(request, config.State)
	if stateError != nil {
		return nil, stateError
	}
	code := GetCode(request)
	token, tokenError := GetToken(request, &config.Config, code)
	if tokenError != nil {
		return nil, tokenError
	}
	var (
		respBody  io.ReadCloser
		respError error
	)
	switch sendThrough {
	case QueryString:
		respBody, respError = SendRequestByQueryString(request, token.AccessToken, config.GetInfoURL, config.RequestMethod, config.Body)
	case AuthorizationBearer:
		respBody, respError = SendRequestByBearer(request, token.AccessToken, config.GetInfoURL, config.RequestMethod, config.Body)
	}
	if respError != nil {
		return nil, respError
	}
	userData, readError := io.ReadAll(respBody)
	if readError != nil {
		return nil, readError
	}
	return userData, nil
}

func SendRequestByBearer(request *http.Request, accessToken, url, requestMethod string, body io.Reader) (io.ReadCloser, error) {
	bearer := "Bearer " + accessToken
	req, reqError := http.NewRequestWithContext(request.Context(), requestMethod, url, body)
	if reqError != nil {
		return nil, reqError
	}
	req.Header.Add("Authorization", bearer)
	client := &http.Client{}
	resp, doClientError := client.Do(req)
	if doClientError != nil {
		return nil, doClientError
	}
	return resp.Body, nil
}

func SendRequestByQueryString(request *http.Request, accessToken, url, requestMethod string, body io.Reader) (io.ReadCloser, error) {
	req, reqError := http.NewRequestWithContext(request.Context(), requestMethod, url+accessToken, body)
	if reqError != nil {
		return nil, reqError
	}
	client := &http.Client{}
	resp, doClientError := client.Do(req)
	if doClientError != nil {
		return nil, doClientError
	}
	return resp.Body, nil
}
