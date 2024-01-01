package main

import "fmt"
import "github.com/digautos/digTotpMiniGo"

var secretid = "yourSecretIdGetFromGithub"

func main() {
	ghTotp := digTotpMiniGo.NewDigMiniTotpForGithub()
	code, err := ghTotp.GenerateTotpCodeNow(secretid)
	if err != nil {
		fmt.Println("generate code  failed: ", err)
	}

	fmt.Println("code: ", code)
}
