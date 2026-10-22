#!/usr/bin/env bash
# Build release binaries, publish a GitHub release, and update the Homebrew
# formula in softway-solutions/homebrew-tap.
#
#   scripts/release.sh v0.1.0
set -euo pipefail

version=${1:?usage: scripts/release.sh vX.Y.Z}
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must look like v1.2.3" >&2; exit 1; }
repo=softway-solutions/sanity-check
tap=softway-solutions/homebrew-tap
root=$(cd "$(dirname "$0")/.." && pwd)
dist=$root/dist
cd "$root"

[[ -z $(git status --porcelain) ]] || { echo "working tree is dirty" >&2; exit 1; }
go test ./...

rm -rf "$dist" && mkdir -p "$dist"
for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 windows/amd64 windows/arm64; do
  os=${target%/*} arch=${target#*/}
  name=sanity-check_${version#v}_${os}_${arch}
  stage=$dist/$name && mkdir -p "$stage"
  bin=sanity-check && [[ $os == windows ]] && bin=sanity-check.exe
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X main.version=${version#v}" -o "$stage/$bin" .
  cp README.md LICENSE "$stage/"
  if [[ $os == windows ]]; then
    (cd "$stage" && zip -q "$dist/$name.zip" ./*)
  else
    tar -C "$stage" -czf "$dist/$name.tar.gz" .
  fi
  rm -rf "$stage"
done
(cd "$dist" && shasum -a 256 *.tar.gz *.zip > checksums.txt)

git tag -a "$version" -m "$version"
# Push over HTTPS with gh's credentials, so a personal SSH key mapped to
# github.com can't push as the wrong account.
ghgit() { git -c credential.helper= -c credential.helper='!gh auth git-credential' "$@"; }
ghgit push "https://github.com/$repo.git" "$version"
gh release create "$version" --repo "$repo" --title "$version" --generate-notes "$dist"/*.tar.gz "$dist"/*.zip "$dist/checksums.txt"

sha() { awk -v f="sanity-check_${version#v}_$1.tar.gz" '$2==f {print $1}' "$dist/checksums.txt"; }
url=https://github.com/$repo/releases/download/$version/sanity-check_${version#v}

tapdir=$(mktemp -d)
ghgit clone -q "https://github.com/$tap.git" "$tapdir"
mkdir -p "$tapdir/Formula"
cat > "$tapdir/Formula/sanity-check.rb" <<EOF
class SanityCheck < Formula
  desc "Find API keys, passwords and tokens leaked into shell history"
  homepage "https://github.com/$repo"
  version "${version#v}"
  license "MIT"

  on_macos do
    on_arm do
      url "${url}_darwin_arm64.tar.gz"
      sha256 "$(sha darwin_arm64)"
    end
    on_intel do
      url "${url}_darwin_amd64.tar.gz"
      sha256 "$(sha darwin_amd64)"
    end
  end

  on_linux do
    on_arm do
      url "${url}_linux_arm64.tar.gz"
      sha256 "$(sha linux_arm64)"
    end
    on_intel do
      url "${url}_linux_amd64.tar.gz"
      sha256 "$(sha linux_amd64)"
    end
  end

  def install
    bin.install "sanity-check"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sanity-check --version")
    assert_equal "", pipe_output("#{bin}/sanity-check --no-color -", "ls -la\n", 0)
    output = pipe_output("#{bin}/sanity-check --no-color -", "export DB_PASSWORD=Zq8rLm2vKx9\n", 1)
    assert_match "secret-assignment", output
  end
end
EOF
git -C "$tapdir" add Formula/sanity-check.rb
git -C "$tapdir" commit -qm "sanity-check $version"
ghgit -C "$tapdir" push -q
echo "Released $version. Install: brew install $tap/sanity-check" | sed 's#homebrew-tap#tap#'
