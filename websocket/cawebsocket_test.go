package websocket

import (
	"fmt"
	"testing"
)

// //wss://postman.eudev2.cyberarmorsoft.com/waitfornotification/5d817063-096f-4d91-b39b-8665240080af-dav-att-test1
// func CreateWebSocketHandlerMock() *WebSocketHandler {
// 	var websocketURL WebSocketURL
// 	websocketURL.Scheme = "wss"
// 	websocketURL.Host = "postman.eudev2.cyberarmorsoft.com"
// 	websocketURL.Path = fmt.Sprintf("waitfornotification/5d817063-096f-4d91-b39b-8665240080af-dav-att-test1")
// 	websocketURL.ForceQuery = false
// 	return &WebSocketHandler{
// 		data:         make(chan DataSocket),
// 		webSocketURL: websocketURL,
// 	}

// }

//wss://postman.onprem.eudev2.cyberarmorsoft.com/waitfornotification/1e3a88bf-92ce-44f8-914e-cbe71830d566-onprem-test-1
func CreateWebSocketHandlerMock() *WebSocketHandler {
	var websocketURL WebSocketURL
	websocketURL.Scheme = "wss"
	websocketURL.Host = "postman.onprem.eudev3.cyberarmorsoft.com"
	websocketURL.Path = fmt.Sprintf("waitfornotification/1e3a88bf-92ce-44f8-914e-cbe71830d566-onprem-test-1")
	websocketURL.ForceQuery = false
	return &WebSocketHandler{
		data:         make(chan DataSocket),
		webSocketURL: websocketURL,
	}

}
func TestDoNothoing1(t *testing.T) {
	// wsh := CreateWebSocketHandlerMock()
	// cautils.CA_IGNORE_VERIFY_CACLI = true
	// if _, err := wsh.dialWebSocket(); err != nil {
	// 	t.Errorf("%v", err)
	// }
}
