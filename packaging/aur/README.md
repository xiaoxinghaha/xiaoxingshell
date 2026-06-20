# 发布到 AUR（xiaoxingshell-bin）

仓库里已经备好 `PKGBUILD` 和发布工作流 `.github/workflows/aur-publish.yml`，
走的是 **-bin 二进制包**：直接安装 GitHub Release 里预编译好的 Linux tar.gz，
Arch 用户不用自己编译 Rust + Slint。

剩下的几步只能你来做（涉及你的 AUR 账号身份）。配好之后，**以后每次发 Release
就会自动同步到 AUR**。

## 一次性配置

### 1. 注册 AUR 账号并加 SSH 公钥
- 在 https://aur.archlinux.org 注册账号。
- 本地生成一把专用 SSH key（**不要**复用日常 key）：
  ```sh
  ssh-keygen -t ed25519 -f ~/.ssh/aur -C "meatshell-aur"
  ```
- 把 **公钥** `~/.ssh/aur.pub` 的内容贴到 AUR 账号设置的「SSH Public Key」里。

### 2. 在 GitHub 仓库加 3 个 Secret
仓库 → Settings → Secrets and variables → Actions → New repository secret：
| 名称 | 值 |
|------|----|
| `AUR_USERNAME` | 你的 AUR 用户名 |
| `AUR_EMAIL` | 你的邮箱 |
| `AUR_SSH_PRIVATE_KEY` | `~/.ssh/aur` **私钥**的完整内容 |

> 没配 `AUR_SSH_PRIVATE_KEY` 之前，发布工作流会**自动跳过**那一步，不会报错。

### 3. 首次手动创建 AUR 包仓库
AUR 上必须先存在 `xiaoxingshell-bin` 这个包，工作流才能 push 更新。第一次手动建：
```sh
git clone ssh://aur@aur.archlinux.org/xiaoxingshell-bin.git
cd xiaoxingshell-bin
# 把本仓库的 packaging/aur/PKGBUILD 复制进来，按需把 pkgver 改成最新 release 版本
cp /path/to/meatshell/packaging/aur/PKGBUILD .
# 填邮箱、刷新校验和、生成 .SRCINFO
updpkgsums
makepkg --printsrcinfo > .SRCINFO
# 本地装一下验证能跑
makepkg -si
# 推到 AUR
git add PKGBUILD .SRCINFO
git commit -m "Initial import: xiaoxingshell-bin"
git push
```

### 4. 改 PKGBUILD 里的维护者邮箱
`PKGBUILD` 顶部 `# Maintainer:` 把 `REPLACE_WITH_YOUR_EMAIL` 换成你的邮箱
（提交到本仓库即可，工作流会用它）。

## 之后

发布新版本（推 `vX.Y.Z` tag → Release 工作流出包并 publish Release）后，
`aur-publish.yml` 会自动：把 `pkgver` 改成新版本 → `updpkgsums` 刷新校验和 →
生成 `.SRCINFO` → push 到 AUR。

也可以在 Actions 里手动触发 `Publish to AUR`（可填指定版本）补发。

## 备注
- 包名用 `xiaoxingshell-bin`（二进制包惯例）。若以后想要从源码编译的 `meatshell`
  包，可另加一份从源码 `makepkg` 的 PKGBUILD（需要 Arch 上有 Rust 工具链 +
  那串 Slint 的 GUI 依赖）。
- ArchLinuxCN 源：在 AUR 稳定后，可以向 archlinuxcn/repo 提 PR 把它纳入二进制源
  （他们会基于 AUR 的 PKGBUILD 打包），那是另外的流程，按其仓库说明走即可。
