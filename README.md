# DosGuard: DoS Attack Detection and Prevention

DosGuard is a localhost-only university Network Security project. It simulates a web server that is configured like a default install, attacks it with three denial-of-service attacks (SYN flood, HTTP flood and Slowloris), and shows how the DosGuard defence system detects and stops each one automatically. A real-time web dashboard lets you launch attacks and watch what happens.

Everything runs inside the computer's memory. No real attack traffic is ever sent to any network.

## What you will see

When you start an attack with protection **off**, legitimate users get locked out. When you switch protection **on**, DosGuard detects the attack within a few seconds and service recovers to about 100%.

## Local services

* Real-time dashboard (frontend and backend): `127.0.0.1:8000`

## Requirements

* Python 3.8 or newer ([python.org/downloads](https://www.python.org/downloads/))
* Git (optional, only needed to clone the project)
* A web browser

There is nothing else to install. The project uses only the Python standard library.

## 1. Get the project

Option A: clone with Git

```
git clone https://github.com/usratjahan/DOS-Attack-Detection-prevention.git
cd DOS-Attack-Detection-prevention
```

Option B: download a ZIP. On the GitHub page click **Code**, then **Download ZIP**, extract it, and open a terminal inside the extracted folder.

Check that you are in the right folder. Run `ls` (or `dir` in PowerShell). You must see:

```
README.md   dosguard   output   tests
```

If you do not see these three items, you are one folder too high or too low. Run `cd` into the folder that contains them.

## 2. Run the real-time dashboard

```
python -m dosguard serve
```

Your browser opens `http://127.0.0.1:8000`. If it does not, paste that address into the browser yourself. Press `Ctrl+C` in the terminal to stop the server.

If `python` is not found, use `py` (Windows) or `python3` (Mac/Linux).

### How to use the dashboard

1. Choose a protection mode: **No protection**, **Monitor** (alerts only) or **DosGuard protect**.
2. Launch an attack: SYN flood, HTTP flood, Slowloris or Distributed HTTP flood.
3. Watch the live charts, server resource bars, event feed and blocked-IP table.
4. Try this: start an **HTTP flood** with "No protection" and see legitimate users drop to about 27%. Then switch to **DosGuard protect** and watch them return to about 100%.
5. Use the speed control to speed up the simulation, and **Reset** to start over.
6. Use the language toggle to switch between English and Bangla.

## 3. Other commands

Run these from the same folder as the dashboard.

```
python -m dosguard demo
python -m dosguard evaluate
python -m dosguard report
python -m dosguard analyze-log output/access_http_flood.log
```

| Command | What it does |
|---|---|
| `demo` | Runs 4 attacks in 3 modes (off, monitor, protect) with charts in the terminal |
| `evaluate` | Prints a randomised evaluation table over many seeds |
| `report` | Builds `output/report.html`. Open this file in a browser |
| `analyze-log` | Applies the HTTP-flood rule to a real nginx/Apache access log and prints block commands |

## 4. Run the tests

```
python -m unittest discover -s tests -v
```

All tests should pass.

## 5. The three attacks

| Attack | Resource exhausted | How it works |
|---|---|---|
| SYN flood | Half-open connection queue | Thousands of TCP SYNs from fake IPs never finish the handshake. Each holds a slot for about 8 seconds |
| HTTP flood | CPU / request workers | Bots complete real connections and send far more requests per second than the server can process |
| Slowloris | Connection slots | Hundreds of connections each send one header byte every ~10 seconds, so none ever finishes |
| Distributed HTTP flood | CPU | 200 bots at only 6 req/s each. Every bot looks polite, so per-IP limits cannot see it |

## 6. How DosGuard defends

Every second the guard looks at what the server saw (SYNs, completed handshakes, requests per IP, open connections) and applies attack-specific rules.

| Rule | Detection signal | Automatic prevention |
|---|---|---|
| `SYN_FLOOD` | 100 or more SYN/s, under 30% complete the handshake, backlog at least 50% full | SYN cookies, so spoofed SYNs cost nothing |
| `HTTP_FLOOD` | One IP at 50 or more req/s for 2 seconds | Temporary IP ban. Repeat offenders get doubling bans (30 s up to 5 min) |
| `GLOBAL_OVERLOAD` | Total load at 90% of capacity or more for 2 seconds | Max-min fair-share rate limit. IPs with a clean history are exempt |
| `SLOWLORIS` | 10 or more connections from one IP still without headers after 3 seconds | Block the IP and kill its connections |
