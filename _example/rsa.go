package main

import (
	"fmt"
	"github.com/module-repo/go-rsa-chunk/rsa"
	"io/ioutil"
)

func main() {
	pri, pub, _ := rsa.GenerateRSA(2048)
	ioutil.WriteFile("pri.key", pri, 0644)
	ioutil.WriteFile("pub.pem", pub, 0644)

	if buf, e := rsa.RSAEncryptBlock([]byte("test"), pub); e == nil {
		if ret, e2 := rsa.RSADecryptBlock(buf, pri); e2 == nil {
			fmt.Println(string(ret))
		}
	}
}
