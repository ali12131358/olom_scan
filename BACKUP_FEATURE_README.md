# Backup feature

See artifacts for full patched files. The file backend/routeros_api.py was accidentally overwritten with PLACEHOLDER and must be restored from the patch package.

Apply the files from the release or copy:
- backend/routeros_api.py
- backend/db.py
- backend/main.py
- frontend/src.jsx
- frontend/style.css

After API probe (خواندن با API), each device stores device_backup (.rsc) and shows a Backup button next to Log.
