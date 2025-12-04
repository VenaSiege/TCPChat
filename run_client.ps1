# TCP 聊天客户端启动脚本 (PowerShell)
# 设置编码为 UTF-8
[Console]::OutputEncoding = [Text.Encoding]::UTF8

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "         TCP 聊天客户端启动" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 检查 Python 是否安装
$pythonCheck = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[错误] 未找到 Python，请先安装 Python 3.6+（https://www.python.org）" -ForegroundColor Red
    Read-Host "按 Enter 键退出"
    exit 1
}

Write-Host "检测到 Python: $pythonCheck" -ForegroundColor Green
Write-Host ""

# 启动客户端
python client.py

Read-Host "按 Enter 键退出"
