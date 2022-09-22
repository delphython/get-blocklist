# Формирование списка доступа для маршрутизатора Cisco 2911.

Для формирования нового 110 access list скрипт забирает выгруженный файл конфигурации маршрутизатора, выбирает из него access-list 110,
очищеает его от старых спам листов. Забирает новые спам листы с [http://www.spamhaus.org](http://www.spamhaus.org) и с
[http://www.dshield.org](http://www.dshield.org), форматирует их в соответствии с форматом access-list и добавляет их в access-list 110.
Затем сформированный файл копирует в папку для дальнейшей загрузки access-list в маршрутизатор. 

## Настройка

Установите зависимости:
```bash
python -m pip install -r requirements.txt
```
## Запуск скрипта

Скрипт запускается через cron каждый день в 00:10:

```bash
10 0 * * * /opt/get-blocklist/venv/bin/python3 /opt/get-blocklist/get-blocklist.py >> /var/log/get-blocklist.log 2>&1
```

## Meta

Vitaly Klyukin — [@delphython](https://t.me/delphython) — [delphython@gmail.com](mailto:delphython@gmail.com)

[https://github.com/delphython](https://github.com/delphython/)
