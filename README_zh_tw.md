# Windows Agent Cleanup

專為 Codex、Claude Code 與其他本機 Agent 設計的 Windows 原生批次清理工具；CLI 與 GUI 共用核心。

一般 Agent 自主安裝請使用官方 **[Latest Release](https://github.com/bestkakkoii/windows_agent_cleanup/releases/latest)**：

1. 下載同一發行紀錄中的 **Windows x64 runtime ZIP** 與對應 `.sha256`。GitHub 自動產生的 **Source code (zip/tar.gz)** 是工程原始碼，不能當成安裝包。
2. **解壓縮前**使用 `Get-FileHash -LiteralPath <下載的ZIP> -Algorithm SHA256`，核對發行紀錄的雜湊；缺少雜湊或不符時停止。
3. Agent 依空間、權限及使用者／專案範圍選擇合適的可攜目錄，沒有指定磁碟或父目錄。沿用已驗證的安裝；替換前先檢查來源與本機修改，優先使用獨立目錄，避免弄髒開發 checkout。
4. 解壓**完整發行包**，將實際絕對入口路徑交給本機 Agent：

```text
read <工具實際所在目錄>/README_AI.md
```

Agent 沿用已提供的清理計畫、範圍與授權，只詢問缺少的選項。一般安裝不下載 `main`／`master` 或原始碼自行編譯，也不需要編譯器、SDK、Python、Node.js、全域 PATH、Skill 註冊或 MCP。安裝與讀取文件不授權刪除；[共用 Skill](skills/project-cleanup/SKILL.md) 是唯一快速操作流程，只有明確開發需求才進入[工程路線](CONTRIBUTING.md#build-from-source)。

快速模式採邏輯刪除；安全抹除須另外明確選用。工具不保證立即回收全部容量、SSD 實體不可復原，或在未量測的硬體上達到最大速度。

**[下載 Windows x64 正式發行 v2.0.0](https://github.com/bestkakkoii/windows_agent_cleanup/releases/tag/v2.0.0)**，使用前核對附帶的 SHA-256 檔案。此版本已標示為 Latest，使用擁有者提供的 GUI／CLI 原檔；程式仍回報 `2.0.0-dev.1`，GUI 保留原有開發建置標籤。擁有者回報 CLI 快速模式已成功清理一批 2,890 個檔案；其他 CLI 驗收與完整硬體矩陣仍待補齊，詳見[發布政策](docs/publication.md)。Release ZIP 包含執行程式、使用文件、協定 schema、授權聲明與完整 Agent Skill；原始碼、建置與測試檔案留在倉庫。CI 測試證據僅代表其記錄的範圍，不會自動授權後續發行。

GUI 使用：啟動 `bin/secure_erase_gui.exe`，選擇 **Quick delete** 或 **Overwrite and verify**，加入／拖放檔案與目錄後按 **Start**。在 **Confirm batch** 檢查並確認；「Frozen targets」代表已固定的目標集合，是正常確認流程。完成的輸入會移出清單，未完成者保留供檢查。失敗時複製診斷 JSON；降級與強制結束程序需要各自的獨立授權。

`README_AI.md` 負責通用入口與導引；完整 Skill 負責清理流程、預設計畫及按需讀取的 CLI 參考文件。可選擇安裝至 Codex 或 Claude Code，無須 MCP。

[English README](README.md) · [Agent 操作／開發入口](README_AI.md) · [架構](docs/design.md) · [回報安全問題](SECURITY.md)

問題回報請使用 [Issues](https://github.com/bestkakkoii/windows_agent_cleanup/issues)，提供發行／程式版本、壓縮包雜湊或實測來源提交、Windows 組建及遮罩後的診斷。開發前閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)；安全問題依 [SECURITY.md](SECURITY.md) 處理。專案由 bestkakkoii 與貢獻者維護，採 [MIT](LICENSE) 授權。
