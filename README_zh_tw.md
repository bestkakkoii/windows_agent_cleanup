# Windows Agent Cleanup

專為 Codex、Claude Code 與其他本機 Agent 設計的 Windows 原生批次清理工具；CLI 與 GUI 共用核心。

將工具放在目標 Windows 電腦後，對 Agent 說：

```text
read C:/tools/windows_agent_cleanup/README_AI.md
```

Agent 會先詢問清理計畫與專案範圍，再依選定規則自主盤點、提交整批名單並回報結果。直接讀取操作文件不需要安裝 Skill 或 MCP。

快速模式採邏輯刪除；安全抹除須另外明確選用。工具不保證立即回收全部容量、SSD 實體不可復原，或在未量測的硬體上達到最大速度。

目前為 RC；正式發布仍須符合 Windows 建置與實機驗收門檻。

[English README](README.md) · [Agent 操作／開發入口](README_AI.md) · [架構](docs/design.md) · [回報安全問題](SECURITY.md)
