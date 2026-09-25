echo Количество открытых файлов:
docker exec -it syslog-app lsof | wc -l
