package msm8916

import (
	"github.com/human-agent65535/nassimhub-node/proto/mmclitext"
	"testing"
)

func TestSMSPropertiesDecodeChineseAndLiteralBackslashes(t *testing.T) {
	for _, text := range []string{"【你好】短信验证😀", `literal\343\200`, "two\nlines"} {
		m, ok := smsFromProperties(smsPathPrefix+"1", "fixture", map[string]string{"sms.properties.pdu-type": "deliver", "sms.properties.state": "received", "sms.content.number": "10000", "sms.content.text": mmclitext.Encode(text)})
		if !ok || m.Text != text {
			t.Fatalf("SMS text changed: %+v", m)
		}
	}
}
