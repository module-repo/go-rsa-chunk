package main

import (
	"encoding/base64"
	"fmt"
	"github.com/module-repo/go-rsa-chunk/rsa"
	"io/ioutil"
)

func main() {
	//pri, pub, _ := rsa.GenerateRSA(2048)
	//ioutil.WriteFile("pri.key", pri, 0644)
	//ioutil.WriteFile("pub.pem", pub, 0644)

	pri, _ := ioutil.ReadFile("pri.key")
	pub, _ := ioutil.ReadFile("pub.pem")

	if buf, e := rsa.RSAEncryptBlock([]byte("test"), pub); e == nil {
		fmt.Println(base64.StdEncoding.EncodeToString(buf))
		if ret, e2 := rsa.RSADecryptBlock(buf, pri); e2 == nil {
			fmt.Println(string(ret))
		} else {
			fmt.Println(e2.Error())
		}
	}
}
