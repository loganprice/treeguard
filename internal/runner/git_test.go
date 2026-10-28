package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	cmds := [][]string{
		{"git", "init"},
		{"git", "config", "user.name", "Test User"},
		{"git", "config", "user.email", "test@example.com"},
	}
	for _, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed command %v: %v (out: %s)", c, err, string(out))
		}
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s failed: %v (out: %s)", strings.Join(args, " "), err, string(out))
	}
}

func TestDiscoverGitChangedFilesTableDriven(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		setupRepo   func(t *testing.T, repoDir string) (targetDir string, baseRef string, changedOnly bool)
		wantFileSub string
		wantCount   int
	}{
		{
			name: "Discover untracked new file",
			setupRepo: func(t *testing.T, repoDir string) (string, string, bool) {
				initGitRepo(t, repoDir)

				// Commit an initial file
				initFile := filepath.Join(repoDir, "initial.py")
				os.WriteFile(initFile, []byte("x = 1\n"), 0644)
				runGit(t, repoDir, "add", "initial.py")
				runGit(t, repoDir, "commit", "-m", "initial commit")

				// Create untracked file
				newFile := filepath.Join(repoDir, "untracked.py")
				os.WriteFile(newFile, []byte("y = 2\n"), 0644)

				return repoDir, "", true
			},
			wantFileSub: "untracked.py",
			wantCount:   1,
		},
		{
			name: "Discover diff against baseline ref",
			setupRepo: func(t *testing.T, repoDir string) (string, string, bool) {
				initGitRepo(t, repoDir)

				// Commit initial file
				initFile := filepath.Join(repoDir, "app.py")
				os.WriteFile(initFile, []byte("x = 1\n"), 0644)
				runGit(t, repoDir, "add", "app.py")
				runGit(t, repoDir, "commit", "-m", "first commit")

				// Modify app.py in second commit
				os.WriteFile(initFile, []byte("x = 2\n"), 0644)
				runGit(t, repoDir, "add", "app.py")
				runGit(t, repoDir, "commit", "-m", "second commit")

				return repoDir, "HEAD~1", false
			},
			wantFileSub: "app.py",
			wantCount:   1,
		},
		{
			name: "Non-git directory returns empty cleanly",
			setupRepo: func(t *testing.T, repoDir string) (string, string, bool) {
				nonGit := filepath.Join(repoDir, "nongit")
				os.MkdirAll(nonGit, 0755)
				os.WriteFile(filepath.Join(nonGit, "test.py"), []byte("z = 3\n"), 0644)
				return nonGit, "", true
			},
			wantFileSub: "",
			wantCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoDir := t.TempDir()
			targetDir, baseRef, changedOnly := tt.setupRepo(t, repoDir)

			files, err := DiscoverGitChangedFiles(ctx, targetDir, baseRef, changedOnly)
			if err != nil {
				t.Fatalf("DiscoverGitChangedFiles failed: %v", err)
			}

			if len(files) != tt.wantCount {
				t.Errorf("Got %d changed files, want %d (files: %v)", len(files), tt.wantCount, files)
			}

			if tt.wantFileSub != "" && len(files) > 0 {
				found := false
				for _, f := range files {
					if strings.Contains(f, tt.wantFileSub) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected files %v to contain %q", files, tt.wantFileSub)
				}
			}
		})
	}
}
