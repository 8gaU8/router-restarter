# Restart Router

A python script to reboot ZXHN F57480 (ZTE) router without browser

## 概要
- コミュファから提供されるホームゲートウェイ(ZTE製ZXHN F57480)を自動で再起動する
- pingを用いてインターネットへの疎通を確認し、一定の条件を満たしたら再起動
- 再起動機能のみを使用したい場合は[`debug.py`](/debug.py)を参照

## 使用方法

- 最初に`.env`ファイルを作成する。
- 例:
```
ROUTER_LOCAL_IP='<ホームゲートウェイのIPアドレス(192.168.0.1)>'
ROUTER_USERNAME='<username(admin)>'
ROUTER_PASSWORD='<password>'
ROUTER_REBOOT_LOG='</path/to/store/logs/router_restarter.log>'
```

### スクリプトとして
```
pip install -r requirements.txt
python3 router_restarter.py
```

### サービスとして
1. `/etc/systemd/system/router-restarter.service`を作成
  - `<>`で囲ってあるところを編集
```
[Unit]
Description=Router Watchdog
After=network.target

[Service]
Type=simple
User=<your user name>
WorkingDirectory=</path/to/your/working-directory>
EnvironmentFile=</path/to/your/.env>
ExecStart=</path/to/python3 /path/to/router_restarter.py>
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

2. systemdを再読み込みしてサービスを有効化
```
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now router-restarter
$ sudo journalctl -u router-restarter -f # ログ確認
```

