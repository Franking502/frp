package framework

import (
	clientsdk "github.com/xxx/yyy/pkg/sdk/client"
)

func (f *Framework) APIClientForFrpc(port int) *clientsdk.Client {
	return clientsdk.New("127.0.0.1", port)
}
