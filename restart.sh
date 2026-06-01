ps aux | grep "nginx_stat.py" | grep -v grep | awk '{print $2}' | xargs -r kill -9
nohup python3 -u nginx_stat.py > /dev/null 2>&1 &
