package wire

import "testing"

func TestParseScanConfig(t *testing.T) {
	got, err := ParseScanConfig([]byte(`{"timeout":"45m","severity":["CRITICAL"]}`))
	if err != nil || string(got) != `{"severity":["CRITICAL"],"timeout":"45m"}` {
		t.Fatalf("got %s, %v", got, err)
	}
	for _, bad := range []string{`{"command":"x"}`, `{"skip_dirs":["-x"]}`, `{"timeout":"1s"}`, `nope`} {
		if _, err := ParseScanConfig([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
