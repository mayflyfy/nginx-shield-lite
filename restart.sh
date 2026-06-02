ps aux | grep "main.py" | grep -v grep | awk '{print $2}' | xargs -r kill -9
nohup python3 -u main.py > /dev/null 2>&1 &
