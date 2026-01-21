# 编译frps
go build -trimpath -ldflags "-s -w" -buildvcs=false  -o bin/frps ./cmd/frps
## 编译frpc
go build -trimpath -ldflags "-s -w" -buildvcs=false  -o bin/frpc ./cmd/c
