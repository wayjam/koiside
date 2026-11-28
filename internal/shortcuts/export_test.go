package shortcuts

import (
	"strings"
	"testing"
)

func TestLaunchURLFormattingAndValidation(t *testing.T) {
	cases := []struct {
		name      string
		target    LaunchTarget
		want      string
		wantValid bool
	}{
		{
			name:      "primary plain",
			target:    LaunchTarget{Folder: "PiliPlus.app"},
			want:      "livecontainer://livecontainer-launch?bundle-name=PiliPlus.app",
			wantValid: true,
		},
		{
			name: "primary with container",
			target: LaunchTarget{
				Folder:          "PiliPlus.app",
				ContainerFolder: "752B6522-37A4-404B-B0C6-8A37556C9F72",
			},
			want:      "livecontainer://livecontainer-launch?bundle-name=PiliPlus.app&container-folder-name=752B6522-37A4-404B-B0C6-8A37556C9F72",
			wantValid: true,
		},
		{
			name: "secondary instance",
			target: LaunchTarget{
				Folder:   "PiliPlus.app",
				Instance: 2,
			},
			want:      "livecontainer2://livecontainer-launch?bundle-name=PiliPlus.app",
			wantValid: true,
		},
		{
			name: "third instance with container",
			target: LaunchTarget{
				Folder:          "PiliPlus.app",
				ContainerFolder: "DATA-2",
				Instance:        3,
			},
			want:      "livecontainer3://livecontainer-launch?bundle-name=PiliPlus.app&container-folder-name=DATA-2",
			wantValid: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LaunchURL(tc.target)
			if got != tc.want {
				t.Fatalf("LaunchURL = %q, want %q", got, tc.want)
			}
			if ValidLaunchURL(got) != tc.wantValid {
				t.Fatalf("ValidLaunchURL(%q) = %v, want %v", got, ValidLaunchURL(got), tc.wantValid)
			}
		})
	}

	invalid := []string{
		"",
		"not-a-url",
		"http://livecontainer-launch?bundle-name=App.app",
		"livecontainer://wrong-host?bundle-name=App.app",
		"livecontainer://livecontainer-launch",
		"livecontainer://livecontainer-launch?bundle-name=",
		"livecontainer://livecontainer-launch?bundle-name=A.app&container-folder-name=",
		"livecontainerX://livecontainer-launch?bundle-name=A.app",
	}
	for _, raw := range invalid {
		if ValidLaunchURL(raw) {
			t.Fatalf("expected %q to be invalid", raw)
		}
	}
}

func TestParseLaunchURLNormalizesLivecontainer1(t *testing.T) {
	u, err := parseLaunchURL("livecontainer1://livecontainer-launch?bundle-name=App.app")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !strings.HasPrefix(u.String(), "livecontainer://") {
		t.Fatalf("expected scheme livecontainer, got %s", u.String())
	}
}
