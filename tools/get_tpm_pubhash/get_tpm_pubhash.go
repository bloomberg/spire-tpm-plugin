/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package main

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"flag"
	"fmt"
	"log"

	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "location of tpm device")
)

func main() {
	flag.Parse()
	pubKey, err := common.GetPubKey(*tpmPath)
	if err != nil {
		log.Fatalln(err)
	}
	asn1Bytes, err := asn1.Marshal(*pubKey)
	if err != nil {
		log.Fatalln(err)
	}

	pubHash := sha256.Sum256(asn1Bytes)
	hashEncoded := base64.StdEncoding.EncodeToString(pubHash[:])

	fmt.Println(hashEncoded)
}
