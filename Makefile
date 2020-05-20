build: cmd/server/tpm_attestor/tpm_attestor.go cmd/agent/tpm_attestor/tpm_attestor.go tools/get_tpm_pubhash/get_tpm_pubhash.go
	GOOS=linux GOARCH=amd64 go build -o tpm_attestor_server cmd/server/tpm_attestor/tpm_attestor.go
	GOOS=linux GOARCH=amd64 go build -o tpm_attestor_agent cmd/agent/tpm_attestor/tpm_attestor.go
	GOOS=linux GOARCH=amd64 go build -o get_tpm_pubhash tools/get_tpm_pubhash/get_tpm_pubhash.go
