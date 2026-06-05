package splithttp_test

import (
	"testing"

	. "github.com/HZ-PRE/XrarCore/transport/internet/splithttp"
)

func Test_GetNormalizedScStreamUpServerSecs(t *testing.T) {
	c := Config{
		ScMinPostsIntervalMs: &RangeConfig{From: 1, To: 2},
		ScStreamUpServerSecs: &RangeConfig{From: 3, To: 4},
	}

	got := c.GetNormalizedScStreamUpServerSecs()
	if got.From != 3 || got.To != 4 {
		t.Error("Unexpected: ", got)
	}
}

func Test_GetNormalizedPath(t *testing.T) {
	c := Config{
		Path: "/?world",
	}

	path := c.GetNormalizedPath()
	if path != "/" {
		t.Error("Unexpected: ", path)
	}
}
