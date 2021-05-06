# Current State

- App fetches everything on startup
- Intention is to have it periodically refresh (but doesn't at this time)
  - If scope of app remains small, just have multiple processes with their own copy
  - If scope grows, use distributed store for instances to share state

# Requirements
- Python3
- python-venv

# How to Run
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
env FLASK_APP=main.py flask run -p 9000
```

## Query
```
curl --request GET \
  --url http://localhost:9000/identities
```

# Stuff I would continue to do if I was doing this at work

- Use an expiring cache or a timer to periodically refresh values
- Use grequests or requests + python-pmap to make http requests simultaneously
- More lru_cache usage possibly
- If heavy use, would have a lambda dump this into s3 or redis periodically and simply dump it at this endpoint


# Stuff I ignored for scope

- threading / multiprocess concerns (including safety)
- refreshing data (ran out of time)
- better handling of errors
- tests
