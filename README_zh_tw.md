# Windows Agent Cleanup

專為 Codex、Claude Code 與其他本機 Agent 設計的 Windows 原生批次清理工具；CLI 與 GUI 共用核心。

將完整發行包解壓至目標 Windows 電腦的合適目錄；Agent 可依可用空間、權限及專案／使用者範圍自行決定，並優先沿用已驗證的既有位置。沒有指定磁碟或父目錄。接著對 Agent 提供實際絕對路徑：

```text
read <工具實際所在目錄>/README_AI.md
```

上述路徑是待替換的示例，不是安裝限制。Agent 會先詢問清理計畫與專案範圍，再依選定規則自主盤點、提交整批名單並回報結果。直接讀取操作文件不需要安裝 Skill 或 MCP。

快速模式採邏輯刪除；安全抹除須另外明確選用。工具不保證立即回收全部容量、SSD 實體不可復原，或在未量測的硬體上達到最大速度。

**[下載 Windows x64 正式發行 v2.0.0](https://github.com/bestkakkoii/windows_agent_cleanup/releases/tag/v2.0.0)**，使用前核對附帶的 SHA-256 檔案。此版本已標示為 Latest，使用擁有者提供的 GUI／CLI 原檔；程式仍回報 `2.0.0-dev.1`，GUI 保留原有開發建置標籤。CLI Agent 驗收與完整硬體矩陣仍待補齊，詳見[發布政策](docs/publication.md)。Release ZIP 包含執行程式、使用文件、協定 schema、授權聲明與完整 Agent Skill；原始碼、建置與測試檔案留在倉庫。CI 測試證據僅代表其記錄的範圍，不會自動授權後續發行。

GUI 使用：啟動 `bin/secure_erase_gui.exe`，選擇 **Quick delete** 或 **Overwrite and verify**，加入／拖放檔案與目錄後按 **Start**。在 **Confirm batch** 檢查並確認；「Frozen targets」代表已固定的目標集合，是正常確認流程。完成的輸入會移出清單，未完成者保留供檢查。失敗時複製診斷 JSON；降級與強制結束程序需要各自的獨立授權。

`README_AI.md` 負責通用入口與導引；完整 Skill 負責清理流程、預設計畫及按需讀取的 CLI 參考文件。可選擇安裝至 Codex 或 Claude Code，無須 MCP。

[English README](README.md) · [Agent 操作／開發入口](README_AI.md) · [架構](docs/design.md) · [回報安全問題](SECURITY.md)

問題回報請使用 [Issues](https://github.com/bestkakkoii/windows_agent_cleanup/issues)，提供發行／程式版本、壓縮包雜湊或實測來源提交、Windows 組建及遮罩後的診斷。開發前閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)；安全問題依 [SECURITY.md](SECURITY.md) 處理。專案由 bestkakkoii 與貢獻者維護，採 [MIT](LICENSE) 授權。
