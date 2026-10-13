#!/usr/bin/env bash
# honeyguard 一键安装脚本（PRD DEP-02/DEP-04）
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/jairwen/honeyguard/main/install.sh | bash
#   curl -fsSL ... | bash -s -- v0.1.0          # 安装指定版本
#   ./install.sh --uninstall                    # 卸载（默认保留配置，--purge 连配置一起删）
#
# 环境变量：
#   HONEYGUARD_REPO   GitHub 仓库（owner/name），默认 jairwen/honeyguard
set -euo pipefail

REPO="${HONEYGUARD_REPO:-jairwen/honeyguard}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/honeyguard"
CONFIG_FILE="$CONFIG_DIR/config.toml"
STATE_DIR="/var/lib/honeyguard"
UNIT_FILE="/etc/systemd/system/honeyguard.service"
SERVICE="honeyguard"

log()  { printf '\033[32m[安装]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[警告]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

uninstall() {
  [ "${1:-}" = "--purge" ] && PURGE=1 || PURGE=0
  command -v systemctl >/dev/null && systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$INSTALL_DIR/honeyguard" "$UNIT_FILE"
  command -v systemctl >/dev/null && systemctl daemon-reload || true
  if [ "$PURGE" = 1 ]; then
    rm -rf "$CONFIG_DIR" "$STATE_DIR"
    log "已卸载 honeyguard（含配置与状态）"
  else
    log "已卸载 honeyguard（配置 $CONFIG_DIR 与状态 $STATE_DIR 已保留）"
  fi
  exit 0
}

[ "${1:-}" = "--uninstall" ] && uninstall "${2:-}"

[ "$(id -u)" = 0 ] || die "请以 root 运行（sudo）"
[ "$(uname -s)" = Linux ] || die "仅支持 Linux"

case "$(uname -m)" in
  x86_64|amd64)   TARGET="x86_64-unknown-linux-musl" ;;
  aarch64|arm64)  TARGET="aarch64-unknown-linux-musl" ;;
  *) die "不支持的架构: $(uname -m)" ;;
esac

[ "$REPO" != "OWNER/honeyguard" ] || die "请先设置仓库：export HONEYGUARD_REPO=<你的GitHub用户名>/honeyguard，或编辑脚本顶部的 REPO 变量"

# ---- 镜像候选：HONEYGUARD_MIRROR 指定时只用它；否则直连优先 + 公共加速回退 ----
MIRROR="${HONEYGUARD_MIRROR:-}"
mirror_list() {
  if [ -n "$MIRROR" ]; then
    printf '%s\n' "${MIRROR%/}/"
  else
    printf '%s\n' "" "https://ghproxy.com/" "https://gh-proxy.com/" "https://ghfast.top/"
  fi
}

# fetch_file <url> <dest>：依次尝试镜像下载
fetch_file() {
  local url="$1" dest="$2" m
  for m in $(mirror_list); do
    if curl -fsSL --connect-timeout 10 "${m}${url}" -o "$dest"; then
      [ -z "$m" ] || log "经镜像下载成功: ${m%/}"
      return 0
    fi
  done
  return 1
}

# fetch_stdout <url>：依次尝试镜像，成功输出响应体
fetch_stdout() {
  local url="$1" m
  for m in $(mirror_list); do
    if curl -fsSL --connect-timeout 10 "${m}${url}"; then
      return 0
    fi
  done
  return 1
}

# ---- 版本解析：参数指定 > 最新 release ----
VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  log "查询最新版本…"
  VERSION="$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"v\([^"]*\)"/\1/')"
  [ -n "$VERSION" ] || die "无法获取最新版本（仓库 $REPO 是否已有 release？网络不通可设置 HONEYGUARD_MIRROR）"
fi

BASE_URL="https://github.com/$REPO/releases/download/v$VERSION/honeyguard-$TARGET"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log "下载 honeyguard v$VERSION ($TARGET)（直连失败自动切换镜像）…"
fetch_file "$BASE_URL.tar.gz"        "$TMP/pkg.tar.gz"  || die "下载失败（可设置 HONEYGUARD_MIRROR 指定镜像）"
fetch_file "$BASE_URL.tar.gz.sha256" "$TMP/pkg.sha256"  || die "下载校验文件失败"

# ---- sha256 校验 ----
EXPECTED="$(awk '{print $1}' "$TMP/pkg.sha256")"
ACTUAL="$(sha256sum "$TMP/pkg.tar.gz" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$TMP/pkg.tar.gz" | awk '{print $1}')"
[ "$EXPECTED" = "$ACTUAL" ] || die "sha256 校验失败（期望 $EXPECTED，实际 $ACTUAL）"
log "sha256 校验通过"

tar -xzf "$TMP/pkg.tar.gz" -C "$TMP"
BIN="$TMP/honeyguard-$TARGET/honeyguard"
[ -f "$BIN" ] || die "压缩包结构异常：未找到 honeyguard 二进制"

# ---- 安装 ----
install -m 0755 "$BIN" "$INSTALL_DIR/honeyguard"
log "二进制已安装: $INSTALL_DIR/honeyguard ($($INSTALL_DIR/honeyguard version 2>/dev/null | head -1))"

if [ ! -f "$CONFIG_FILE" ]; then
  mkdir -p "$CONFIG_DIR"
  EXAMPLE="$TMP/honeyguard-$TARGET/config.example.toml"
  [ -f "$EXAMPLE" ] || EXAMPLE=""
  if [ -n "$EXAMPLE" ]; then
    install -m 0600 "$EXAMPLE" "$CONFIG_FILE"
  else
    printf '# honeyguard 配置，字段说明见 https://github.com/%s\n' "$REPO" > "$CONFIG_FILE"
  fi
  chmod 0600 "$CONFIG_FILE"
  log "已生成默认配置: $CONFIG_FILE（记得填入你的 Webhook）"
else
  log "配置已存在，保留不动: $CONFIG_FILE"
fi
mkdir -p "$STATE_DIR" && chmod 0700 "$STATE_DIR"

# ---- systemd ----
if command -v systemctl >/dev/null; then
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=honeyguard - lightweight VPS intrusion detection agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/honeyguard run
Restart=always
RestartSec=5
# stderr/stdout 自动进入 journald：journalctl -u honeyguard -f
DynamicUser=no

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$SERVICE"
  log "systemd 服务已启用并启动: $SERVICE"
  sleep 1
  systemctl is-active --quiet "$SERVICE" && log "服务运行中 ✓" || warn "服务未处于 active 状态，请检查: journalctl -u $SERVICE -n 50"
else
  warn "未检测到 systemd，请自行以 root 运行: $INSTALL_DIR/honeyguard run"
fi

cat <<EOF

安装完成。接下来：
  1. 编辑 $CONFIG_FILE 填入你的 Webhook（钉钉/飞书/企业微信/Slack/自定义）
  2. 发送测试告警验证通道: $INSTALL_DIR/honeyguard test-alert
  3. 查看日志: journalctl -u $SERVICE -f
后续升级一条命令: sudo honeyguard update（或 honeyguard update --check 先看有没有新版）
EOF
