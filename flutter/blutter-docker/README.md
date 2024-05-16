Copy your sample in `/tmp/blutter`.

```
docker compose build
docker compose run blutter
```

Then, in the container, 

```
cd blutter
python3 blutter.py ../lib/arm64-v8a/ ../blutter-out
```


