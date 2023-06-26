# Safeblog

Challenge doesn't require instances - intended solution is to forge a session cookie to access admin post with flag. Docker is protected from interaction with flag file by CTF user.

It is unknown how many people can use this service at the same time. Theres Flask-Limiter that allows to run /export and /import endpoints only 10 times per minute. **This needs to be tested with our infrastructure if user IP is passed correctly**.

## Server

Start docker with a server using docker-compose command:
```bash
cd docker
docker-compose up -d 
```

Web server is exposed on :8080

## Solver

```bash
cd solver
docker build --rm -t safeblog_solver .
docker run safeblog_solver IP PORT 
```