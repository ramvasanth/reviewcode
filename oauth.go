package oauth2
import (
"encoding/json"
"errors"
"fmt"
"io/ioutil"
"net/http"
"sync"
"razer/csr-sign/auth/client"
"razer/csr-sign/config"
)
var httpClient *http.Client
var once sync.Once
func init() {
httpClient = client.GetHTTP()
}
//SetHTTP can be used to set the HTTP client to override the default http.client
func SetHTTP(c *http.Client) {
setClient := func() {
if c != nil {
httpClient = c
}
}
once.Do(setClient)
}
//Valid - validate the oauth2 token
func Valid(token string) (Response, error) {
requestURL := fmt.Sprintf("%s%s?access_token=%s", config.AppCfg.OAuth2.Host, config.AppCfg.OAuth2.ValidationURI, token)
req, _ := http.NewRequest("GET", requestURL, nil)
resp, err := httpClient.Do(req)
response := Response{}
if err != nil {
return response, err
}
defer resp.Body.Close()
respByte, _ := ioutil.ReadAll(resp.Body)
response.Message = string(respByte)
if len(respByte) == 0 {
return response, errors.New("no response is received from oauth2 server : ")
}
err = json.Unmarshal(respByte, &response)
if err != nil {
return response, err
}
if resp.StatusCode == 200 && response.UUID != "" {
response.IsAuthorized = true
response.Token = token
return response, nil
}
return response, errors.New(string(respByte))
}
