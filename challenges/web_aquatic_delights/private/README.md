# Aquatic Delights

**Challenge requires instances** - each user should have its own shop. Intended solution is to race-condition `eat` (without DB semaphore) with `sell` (with DB semaphore), this requires specific libraries rewriting TCP communication that allows to send requests with lowest possible latency to each other. It should be hard to exploit without that library, because spamming `eat` in a "hope" to race-condition would delete all fishes from inventory.

If task doesn't get solved until X then here's proposition for a clue:

More reasons to visit our shop:

* **Regular** consumption of fishes has been associated with a reduced risk of various diseases, such as heart disease,
* **Astonishing** variety of fishes that will captivate any aquatic enthusiast,
* **Culinary** delights await elevating your dining experience to new heights,
* **Experience** the exceptional quality and freshness ensuring a memorable culinary journey.

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
docker build --rm -t aquatic_delights_solver .
docker run aquatic_delights_solver IP PORT 
```
