Reusable HTB writeup template (use for each box)
1.	Title / Box name: Intentions

2.	Objective (what you tested / why)

3.	Tools & environment (versions, VM notes)
     nmap, curl, Gobuster

4.	Enumeration (commands & key outputs)
    SSH and http services available
    Found that shh and http is avaialble in target HTB machine. 
    Choosing http path as web is already exposed by the machine.

    Web app Details
    Login / Register form | input fields present, user creation possibility
    Tech Stack: Nginx server 1.18, JS framework, Ubuntu server
    Inspect Page: Login.js src="/js/login.js", mdb.js src="/js/mdb.js" loads by default

    Hidden Directory Enumeration:
    Gobuster
    gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,txt,html -o gobuster.txt
    robots.txt file found->User-agent: * Disallow:
    storage folder found but forbidden to access

    Exploring the Web app
    created new user with random name, email id and pwd
    email id field required @xxx.com to be there in the value passed
    http://IP/gallery#/ is the landing page for the user home page display: Welcome Welcome to our humble image gallery! We will be adding new images weekly from a broad swathe of interests. Be sure to check back regularly! http://IP/gallery#/gallery , /feed are the directories shown up pon clicking the links
    Inspect Page: src="/storage/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg"
                  /storage/food/anto-meneghini-sJ4ix9_AjAc-unsplash.jpg
    no error thrown when trying to login with mail id without @domain name but it does not login
    invalid cred error thrown if wrong mail id with @domain.com is passed

    upon successuful user login- login.js initiates the gallery.js script and navigates to gallery file http://10.129.146.22/js/gallery.js Headers Cookie: XSRF token Referer http://10.129.146.22/gallery three cookies under cookies tab found intentions_session: toke: XSRF_token Note: intentions is the HTB box name
    upon clicking gallery tab ->gallery.js initiates images file and loads all .jpg files from /storage folder filename : /storage/architecture/leopold-baskarad-BcIr38tPxJ8-unsplash.jpg there are subfolders like animals, architecture under storage folder to load respective grouped images
    /api/v1/auth/login /api/v1/auth/register
    upon clicking Feed tab listed under Home page we see gallery.js initiated feed file filename : /api/v1/gallery/user/feed Api endpoint exposed
    gallery.js->view page source-> search for "/api" to learn more about other API endpoints
    found the below through Source page this;axios.post("/api/v1/gallery/user/genres", his;axios.get("/api/v1/gallery/images" this;axios.get("/api/v1/gallery/user/feed this;axios.get("/api/v1/auth/user").then((function(e){t.name=e.data.data.name,t.email=e.data.data.email,t.genres=e.data.data.genres}))

    upon visiting /api/v1/auth/user {"status":"success","data":{"id":28,"name":"xxx","email":"xxxx@gmail.com","created_at":"2025-10-30T08:56:03.000000Z","updated_at":"2025-10-30T08:56:03.000000Z","admin":0,"genres":"food,travel,nature"}}

5.	Exploitation steps (exact commands/payloads)
      nmap IP
    nmap -sC -sV -p- --min-rate=1000 IP

6.	Privilege escalation (steps & proof)
7.	Detection / Telemetry (what logs look like, SIEM rules)
8.	Root cause & mapped interview topics (pick 3–5 from your 30)
9.	Fixes & mitigations (code/config examples)
10.	CV/Interview bullet (1–2 lines: impact + action)
11.	Link to PoC code / scripts
