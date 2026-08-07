//go:build linux

package identity

import "testing"

// TestExtractContainerHexID covers the cgroup formats we actually see in
// the wild. The previous implementation took the last path segment and
// truncated to 12 — broken on systemd-managed Docker (returned things
// like "docker-abcde") and any layout where the container ID is followed
// by a suffix like ".scope". The regex-based extractor pulls the longest
// hex run regardless of surrounding noise.
func TestExtractContainerHexID(t *testing.T) {
	full := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "systemd cgroup v2 docker .scope",
			in:   "0::/system.slice/docker-" + full + ".scope",
			want: full[:12],
		},
		{
			name: "systemd cgroup v2 cri-containerd .scope",
			in:   "0::/system.slice/cri-containerd-" + full + ".scope",
			want: full[:12],
		},
		{
			name: "cgroup v1 /docker/<id>",
			in:   "1:name=systemd:/docker/" + full,
			want: full[:12],
		},
		{
			name: "kubernetes containerd pod scope",
			in:   "0::/kubepods.slice/kubepods-besteffort.slice/cri-containerd-" + full + ".scope",
			want: full[:12],
		},
		{
			name: "no container — user session",
			in:   "0::/user.slice/user-1000.slice/session-1.scope",
			want: "",
		},
		{
			name: "docker keyword without hex id",
			in:   "0::/system.slice/docker.service",
			want: "",
		},
		{
			name: "multiple lines, picks first match",
			in:   "0::/init.scope\n1:name=systemd:/docker/" + full,
			want: full[:12],
		},
		{
			// Real /proc/<pid>/mountinfo line from Docker Desktop:
			// the container's resolv.conf is bind-mounted from
			// /docker/containers/<id>/resolv.conf on the host.
			// Modern Docker namespaces cgroup so cgroup file is
			// "0::/", but mountinfo still leaks the container ID.
			name: "mountinfo docker bind mount",
			in:   "177 168 254:1 /docker/containers/" + full + "/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw,discard",
			want: full[:12],
		},
		{
			// overlayfs source path on Docker Desktop's containerd
			// snapshotter — has "containerd" keyword but no 64-hex
			// container ID (only snapshot numbers). Must return ""
			// so we don't poison the hash with a non-id.
			name: "mountinfo overlay snapshotter without container id",
			in:   "168 100 0:65 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/218/fs",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractContainerHexID(tc.in); got != tc.want {
				t.Errorf("extractContainerHexID() = %q, want %q", got, tc.want)
			}
		})
	}
}
