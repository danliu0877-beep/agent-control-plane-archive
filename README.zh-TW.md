# Agent Control Plane（ACP）

這是一個已停止開發的 AI 跨專案協調實驗。

當初做 ACP，是想減少我在不同專案之間協調 AI 工作的麻煩。dot 出來之後，我發現沒有必要繼續做下去了。這份程式碼留下來供參考，不把它包裝成已完成的產品。

採用 [MIT 授權](LICENSE)，版權署名為 danliu0877-beep。

## 實際做了什麼

- Python 標準函式庫 CLI、SQLite 狀態與稽核紀錄。
- 專案解析、受限脈絡載入與規劃提案。
- 任務相依圖、有限度並行、明確的人工批准與驗收。
- Synthetic 測試情境的獨立 review、重試及本機控制面板。

這個版本以 M12 主線為基礎。M13A 的 live provider 認證分支尚未完成，也沒有納入。測試通過不代表真實專案執行、VM 隔離或 live API 已經驗證。

## 使用界線

只適合單人、本機、可丟棄的測試情境。不要公開控制面板、放正式憑證、讓它操作真實專案或拿去當通用 sandbox。VMware 程式保留為歷史實驗程式，不能當成裝好就能安全使用的執行環境。

需要 Python 3.12+ 與 Git，沒有第三方 Python runtime 套件。啟動與測試指令請看 [英文 README](README.md)。這份程式碼沒有承諾後續維護。

## 整理方式

原私人專案與 Git 歷史保留不動。這份候選快照移除了實際採購脈絡、私人試跑資料與主機驗證報告，只保留程式、synthetic 測試和重新整理的說明。清理造成的證據限制列在 [公開範圍](docs/RELEASE_SCOPE.md)。

## 授權

[MIT License](LICENSE)，Copyright (c) 2026 danliu0877-beep。外部工具仍適用各自的授權條款。
