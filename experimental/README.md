# Experimental LTSC 26340.9616 — zh-CN x64

这是独立的研究与离线试构建入口。没有修改 `.github/version-config.json`、`auto_patch.yml` 或正式 LTSC 矩阵，也不会 dispatch 上游、创建发行版、上传 ISO、激活系统或修改安装后配置。

**当前状态：research。已实现构建驱动，尚未证明可原生集成，也没有通过安装验收的 ISO。** 它不属于微软支持的 LTSC 版本。微软正式 LTSC 2024 是 24H2/26100 系列；不要把本项目的输出用于主力系统。

## 已确认与仍需确认

- [Microsoft 2026-10-07 公告](https://blogs.windows.com/windows-insider/2026/10/07/announcing-new-builds-for-7-october-2026/)及[官方发布说明](https://learn.microsoft.com/en-us/windows-insider/release-notes/experimental/preview-build-26340-9616)确认 Experimental 26340.9616。
- [UUP dump 的 x64 索引](https://uupdump.net/findfiles.php?id=398e3bc2-9c3f-4d87-b40b-e54a46826056&q=!updates)是第三方索引。Microsoft CDN 包字节的静态 MUM/CompDB 支持：KB5122055 检查点 `26100.6 → 26100.1746`，KB5127753 `26100.1746 → 26100.9616`，KB5122776 启用 `26340.0`。首版顺序为检查点、LCU、EKB，并保留 MSU 内含 SSU。不能只下载两个包。
- EKB `update.mum` 父包包含 `EnterpriseSEdition`，这是值得进行原生试验的依据。CAT 静态链为 Microsoft Windows / Microsoft Development PCA 2014；**不是默认 Windows 信任检查或实际 DISM applicability 已通过的证明**。
- 未找到两个 KB 的独立 Microsoft Support 文章；Catalog 精确查询未返回结果。不能据此判定包不存在，也不能冒充正式 LTSC 支持声明。

`evidence/` 存放去临时 URL 的元数据、MUM、CompDB 和关联仓库审计。XML 是源材料，未作为脚本执行；CAT 完整性/成员关系和实际适用性由 Windows 原生检查继续验证。

## 作者的原始 ISO 可以复用吗

作者从 [win_iso_zip 的简中 x64 Release](https://github.com/adavak/win_iso_zip/releases/tag/Windows_11_LTSC_2024_X64_ZH-CN) 下载 3 个 ZIP 分卷，合并后校验固定 SHA256，再调用 `Start.cmd`。本路线保留其候选镜像来源，新增各分卷 digest、大小、单一 ZIP 成员与完整 ISO SHA256 校验。

ISO 名为 `zh-cn_windows_11_enterprise_ltsc_2024_x64_dvd_cff9cd2d.iso`，5287520256 bytes。SHA256 `2cb21649590c8cf770cd93556596dff4fd800f24d267a9be9d9ce0ee9e03f5ac` 来自作者 pinned 配置，尚未独立对照微软订阅下载元数据。作者 Release 未提供来源说明。哈希一致证明文件与锁定参照一致；文件名或 GitHub 托管不能证明微软来源、使用许可或重新分发许可。

可把作者文件作为**明确标注来源的候选原始介质**用于隔离试验；安装使用仍须符合你持有的 Windows 许可。不提供密钥或激活绕过。如需官方试用，可使用 [Microsoft Eval Center](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise)；评估版是 `EnterpriseSEval`，不能用当前 EnterpriseS 锁直接替代，必须独立配置并保留评估身份。

## 获取与核验（Python 3.9+）

```text
python experimental/prepare.py validate
python experimental/prepare.py acquire-base --destination C:\LTSC-input\base
python experimental/prepare.py acquire-packages --only-enablement --destination C:\LTSC-input\ekb
```

获取器不会运行下载内容。UUP 的临时签名 URL 只在内存中使用。它把原始 path/query 映射到 `https://catalog.sf.dl.delivery.mp.microsoft.com`，保持 TLS 证书校验，再核对锁定 SHA256/SHA1/大小。小 EKB 的等价 HTTPS 字节已验证；其他包可能返回 403，遇到拒绝或哈希漂移直接停止，不回退 HTTP、不关闭证书校验。

```powershell
.\experimental\Inspect-EnablementPackage.ps1 `
  -PackagePath C:\LTSC-input\ekb\Windows11.0-KB5122776-x64.cab `
  -OutputDirectory C:\LTSC-evidence\ekb-unique
```

此命令只展开 CAB、读取 MUM 和检查 CAT。默认信任若拒绝，报告保留失败；不得导入开发根、修改 flight signing 或打开 testsigning。有效 CAT 签名仍不等于整个包可服务 LTSC。GitHub 手动 `Experimental LTSC source and Windows audit` 工作流运行相同检查，权限只有 `contents: read`，并保留失败证据。

## 原生离线试构建入口

先完成 Windows CAT 预检和依赖审核，记录证据，经代码审查将锁的 `status` 改为 `ready-for-offline-trial`。这只是允许原生试验，不是宣告兼容成功。随后获取全部锁定包（去掉 `--only-enablement`），在**Windows x64 24H2+**、管理员 PowerShell、至少 60GB 可用空间、已安装 Microsoft ADK 的环境运行。Python 只负责锁校验；DISM 来自该 Windows 主机，oscdimg 必须有有效 Microsoft 签名。

```powershell
# 默认只显示计划
.\experimental\Build-Ltsc.ps1
# 使用新的、专用于这次试验的目录；原始输入不会被修改
.\experimental\Build-Ltsc.ps1 -Apply `
  -BaseIso C:\LTSC-input\base\zh-cn_windows_11_enterprise_ltsc_2024_x64_dvd_cff9cd2d.iso `
  -PackageDirectory C:\LTSC-input\packages `
  -WorkDirectory C:\LTSC-trials\run-unique `
  -OscdimgPath 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe' `
  -AcceptUnverifiedMirrorProvenance
```

`-AcceptUnverifiedMirrorProvenance` 表示已读过候选镜像来源限制，不授予任何 Windows 许可。选择微软授权渠道原 ISO且哈希相同后，可在审核记录中补充来源佐证，而非盲目把 flag 设为 true。

驱动只选择 `EnterpriseS/x64/zh-CN/26100` 索引，在新副本中原生 `Add-Package`，不使用 `IgnoreCheck` 或子 MUM 强装。CAB 检查 `Applicable: Yes`；MSU 不支持 `Get-PackageInfo`，由 `Add-Package` 默认检查并复读包状态。检查点 MSU 分组只允许审核过的兄弟文件。任何失败停止并丢弃挂载更改，保留日志。读取离线 Edition/CurrentBuildNumber/UBR、核验目标 `26340.9616/EnterpriseS`、检查组件健康后才生成带 `UNOFFICIAL-EXPERIMENTAL` 名称的 ISO。如果版本变更需首次启动才能完成，首版会保守拒绝输出，先研究 CBS 状态。

**MVP 仅服务 install.wim。boot.wim、Setup 和 WinRE 保留原始版本**；后续需要独立验证 Setup/SafeOS 更新与恢复环境。输入与配方固定可重现；并未保证 DISM/oscdimg 输出逐字节相同，日志会记录主机版本、工具哈希、包状态和 ISO 哈希。

没有激进精简、ResetBase、注册表优化、ACL 重置、移除 ShellNew、禁用更新或网络组件。未发现原作者脚本直接重置 Users ACL；此前权限问题的具体根因仍需原系统证据，不能归因于构建号或本仓库。

安装后按 [ACCEPTANCE.md](ACCEPTANCE.md) 在快照 VM 内验证 ACL、Explorer 新建菜单、Windows Update、Reality/sing-box。自动采集器不会自动给出整体通过。

## 开发验证

```text
python -m unittest discover -s tests -v
git diff --check
```

手动 Windows audit 工作流还用 PowerShell 5.1/7 解析全部脚本并验证研究锁确实拒绝 `-Apply`。这些检查不代替原生离线集成、启动与网络实测。
