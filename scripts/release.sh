#!/usr/bin/env bash
# Build and publish a release, then update the Homebrew formula.
#
#   scripts/release.sh 0.1.0 [path to a WebDecoy/homebrew-tap checkout]
#
# Needs gh signed in with push access to WebDecoy/cli and WebDecoy/homebrew-tap.
set -euo pipefail
version="${1:?usage: release.sh <version> [tap checkout]}"
tap="${2:-}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be X.Y.Z" >&2; exit 1; }
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean" >&2; exit 1; }

GOWORK=off go test ./... -count=1
rm -rf dist && mkdir dist
for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do
  os="${target%/*}" arch="${target#*/}"
  work="$(mktemp -d)"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOWORK=off go build -trimpath \
    -ldflags "-s -w -X main.Version=$version" -o "$work/webdecoy" ./cmd/webdecoy
  cp LICENSE README.md "$work/"
  tar -C "$work" -czf "dist/webdecoy_${version}_${os}_${arch}.tar.gz" webdecoy LICENSE README.md
  rm -rf "$work"
done
(cd dist && shasum -a 256 *.tar.gz > checksums.txt)

git tag -a "v$version" -m "webdecoy $version"
git push origin "v$version"
gh release create "v$version" dist/* --title "webdecoy $version" --notes "webdecoy $version. Install: brew install webdecoy/tap/webdecoy"

[ -n "$tap" ] || { echo "released; no tap checkout given, formula not updated"; exit 0; }
sum() { grep "_$1.tar.gz" dist/checksums.txt | cut -d' ' -f1; }
base="https://github.com/WebDecoy/cli/releases/download/v$version"
mkdir -p "$tap/Formula"
cat > "$tap/Formula/webdecoy.rb" <<RUBY
class Webdecoy < Formula
  desc "Sign in to WebDecoy and run its MCP server locally for AI assistants"
  homepage "https://github.com/WebDecoy/cli"
  version "$version"
  license "MIT"

  on_macos do
    on_arm do
      url "$base/webdecoy_${version}_darwin_arm64.tar.gz"
      sha256 "$(sum darwin_arm64)"
    end
    on_intel do
      url "$base/webdecoy_${version}_darwin_amd64.tar.gz"
      sha256 "$(sum darwin_amd64)"
    end
  end

  on_linux do
    on_arm do
      url "$base/webdecoy_${version}_linux_arm64.tar.gz"
      sha256 "$(sum linux_arm64)"
    end
    on_intel do
      url "$base/webdecoy_${version}_linux_amd64.tar.gz"
      sha256 "$(sum linux_amd64)"
    end
  end

  def install
    bin.install "webdecoy"
  end

  def caveats
    on_linux do
      "webdecoy stores its login with secret-tool: install libsecret-tools and run a Secret Service."
    end
  end

  test do
    assert_match "webdecoy #{version}", shell_output("#{bin}/webdecoy version")
  end
end
RUBY
(cd "$tap" && git add Formula/webdecoy.rb && git commit -m "webdecoy $version" && git push)
echo "released $version and updated the tap"
