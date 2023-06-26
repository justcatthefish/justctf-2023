package main

import (
	"testing"
)

func TestIsSafeHTML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "Simple text with no tags",
			input: "Hello, world!",
			want:  true,
		},
		{
			name:  "Safe tags with no attributes",
			input: "<h1>Hello</h1><p>World</p>",
			want:  true,
		},
		{
			name:  "Tag with attribute",
			input: `<h1 id="greeting">Hello</h1>`,
			want:  false,
		},
		{
			name:  "Non-allowed tag",
			input: "<script>alert('Hello, world!')</script>",
			want:  false,
		},
		{
			name:  "Self-closing tag with no attribute",
			input: "<img/>",
			want:  true,
		},
		{
			name:  "Self-closing tag with attribute",
			input: `<img src="image.jpg"/>`,
			want:  false,
		},
		{
			name:  "SVG with onload",
			input: `<svg onload="alert(document.cookie)"></svg>`,
			want:  false,
		},
		{
			name:  "Nested script tag",
			input: `<svg><textarea><script>alert(document.domain)</script></textarea></svg>%`,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSafeHTML(tt.input); got != tt.want {
				t.Errorf("isSafeHTML(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
