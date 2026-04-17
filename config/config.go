package config

import "github.com/pulumi/pulumi-go-provider/infer"

type Config struct {
	HsmLocation string `pulumi:"hsmLocation"`
	HsmPin      string `pulumi:"hsmPin" provider:"secret"`
}

func (c *Config) Annotate(a infer.Annotator) {
	a.Describe(&c.HsmLocation, "HSM Library Location e.g. /usr/lib/softhsm/libsofthsm2.so")
	a.Describe(&c.HsmPin, "PIN for authentication to the PKCS#11 token")
}
