# GTB Plugins

GTB-owned code integrated into Hermes Agent. Protected — never overwrite on upstream sync.

| Component | Location | Description |
|-----------|----------|-------------|
| MTProto adapter | `../gateway/platforms/telegram_mtproto.py` | Telegram MTProto platform adapter |
| catboy preset | `../hermes/personalities/` | catboy/chaoscat personality presets |

## Upstream sync rule
After pulling from NousResearch upstream, verify these files are intact:
- `gateway/platforms/telegram_mtproto.py`
- personality preset files (catboy, chaoscat)
