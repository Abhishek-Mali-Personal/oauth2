package main

import (
	"fmt"
	auth "github.com/Abhishek-Mali-Simform/oauth2"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	googleConf    = &auth.ConfigureOAuth2{}
	microsoftConf = &auth.ConfigureOAuth2{}
)

func init() {
	// Load .env file
	envError := godotenv.Load(".env")
	if envError != nil {
		log.Fatal("Error loading .env file", envError)
	}
	googleConf.ClientID = os.Getenv("GOOGLE_CLIENT_ID")
	googleConf.ClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	googleConf.RedirectURL = os.Getenv("GOOGLE_REDIRECT_URL")
	googleConf.Scopes = strings.Split(os.Getenv("GOOGLE_SCOPES"), ",")
	googleConf.Endpoint = google.Endpoint
	googleConf.State = "randomstate"
	googleConf.GetInfoURL = os.Getenv("GOOGLE_GET_DETAIL_URL") + "?access_token="
	googleConf.RequestMethod = http.MethodGet
	googleConf.Body = http.NoBody
	microsoftConf.ClientID = os.Getenv("MICROSOFT_CLIENT_ID")
	microsoftConf.ClientSecret = os.Getenv("MICROSOFT_CLIENT_SECRET")
	microsoftConf.RedirectURL = os.Getenv("MICROSOFT_REDIRECT_URL")
	microsoftConf.Scopes = strings.Split(os.Getenv("MICROSOFT_SCOPES"), ",")
	microsoftConf.Endpoint = microsoft.AzureADEndpoint(os.Getenv("MICROSOFT_TENANT_ID"))
	microsoftConf.State = "randomstate"
	microsoftConf.GetInfoURL = os.Getenv("MICROSOFT_GET_DETAIL_URL")
	microsoftConf.RequestMethod = http.MethodGet
	microsoftConf.Body = http.NoBody
}

func main() {
	GoogleExample()
	MicrosoftExample()
	log.Println(http.ListenAndServe(":9999", nil))
}

func MicrosoftExample() {
	http.HandleFunc("/microsoft/login", MicrosoftLogin)
	http.HandleFunc("/microsoft/callback", MicrosoftCallback)
}

func GoogleExample() {
	http.HandleFunc("/google/login", GoogleLogin)
	http.HandleFunc("/google/callback", GoogleCallback)
}

func GoogleLogin(writer http.ResponseWriter, request *http.Request) {
	url := auth.Login(googleConf)
	http.Redirect(writer, request, url, 203)
}

func MicrosoftLogin(writer http.ResponseWriter, request *http.Request) {
	url := auth.Login(microsoftConf)
	http.Redirect(writer, request, url, 203)
}

func GoogleCallback(writer http.ResponseWriter, request *http.Request) {
	userInfo, getInfoError := auth.Callback(
		request,
		googleConf,
		auth.QueryString,
	)
	if getInfoError != nil {
		log.Fatalln(getInfoError)
	}
	_, writeError := fmt.Fprintln(writer, string(userInfo))
	if writeError != nil {
		log.Fatalln(writeError)
	}
}
func MicrosoftCallback(writer http.ResponseWriter, request *http.Request) {
	userInfo, getInfoError := auth.Callback(
		request,
		microsoftConf,
		auth.AuthorizationBearer)
	if getInfoError != nil {
		log.Fatalln(getInfoError)
	}
	_, writeError := fmt.Fprintln(writer, string(userInfo))
	if writeError != nil {
		log.Fatalln(writeError)
	}
}
