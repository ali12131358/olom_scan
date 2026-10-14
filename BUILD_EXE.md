# ساخت MikroTikScannerAgent.exe

## خلاصه
روی **ویندوز** با Python 3.10+ یک‌بار `build_exe.bat` را اجرا کنید.
خروجی: `local_agent/dist/MikroTikScannerAgent.exe` — تک‌فایل، بدون نیاز به Python روی کلاینت.

## مراحل
```bat
:: 1) extract local-agent.zip
cd local_agent
:: 2) build
build_exe.bat
:: 3) distribute
:: فقط dist\MikroTikScannerAgent.exe را به کاربران بدهید
```

## معادل دستی
```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt pyinstaller
pyinstaller MikroTikScannerAgent.spec
```

## نکات
- ساخت باید روی **همان OS** هدف باشد (exe ویندوز را روی ویندوز بسازید).
- از این محیط لینوکس نمی‌توان exe ویندوز تولید کرد.
- آنتی‌ویروس ممکن است exe بدون امضا را بلاک کند؛ در صورت نیاز code-sign کنید.
- Agent روی `127.0.0.1:8001` گوش می‌دهد.
