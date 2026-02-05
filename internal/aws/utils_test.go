package aws

import "testing"

func TestFloatPtrToString(t *testing.T) {
	cases := []struct {
		name string
		val  *float64
		want string
	}{
		{name: "nil", val: nil, want: ""},
		{name: "whole", val: floatPtr(1), want: "1"},
		{name: "fraction", val: floatPtr(1.25), want: "1.25"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := floatPtrToString(tc.val); got != tc.want {
				t.Fatalf("floatPtrToString(%v) = %q, want %q", tc.val, got, tc.want)
			}
		})
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "keeps-dashes", in: "My-Instance", want: "my-instance"},
		{name: "drops-symbols", in: "Name@123", want: "name123"},
		{name: "empty", in: "!!!", want: "x"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitize(tc.in); got != tc.want {
				t.Fatalf("sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func floatPtr(v float64) *float64 {
	return &v
}
