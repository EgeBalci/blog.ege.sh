+++
date = '2025-06-16T11:25:13+02:00'
draft = false
cover = "cover.webp"
title = 'How I Track You For Free'
categories = ['security', 'privacy', 'opsec']
+++

Over the years I'have been using many tricks to monitor/log the people reading my posts, social media profiles and Github repositories. I do this mainly to justify my creative efforts, If no one is consuming the things I share then whats the point of sharing anything? Also I like to know who is consuming my content. For example, since you're reading this post, I have a very good idea about you. I roughly know your location, your IP address, which website you're coming from, your device details (operating system, device specs, resources...), your time zone, keyboard layout and many more. In this post I'll show you how I do this with entirely free services and libraries, no hosting, no paid platforms the only thing you need is a domain (even this can be free).

## The Goal: Full Spectrum Web User Tracking

Our main goal is trackign a web user when they click a link about you. This link could be a personal blog, your CV, an alias for socials, or any similar content about you. When the user clicks the link we'll be collecting the following information.

- IP address & geolocation
- Browser/device fingerprint
- Referring website
- On-page interaction (clicks, hovers, scrolls)
- Session analytics
- DNS resolver IP (for detecting DNS leak) # https://dnsleaktest.com/results.html

And yes, this is entirely possible with free tools.






## The Tracking Stack: How It Works

1. IP Address & Geolocation – Cloudflare Workers

Using Cloudflare Workers, you can deploy serverless code that runs before your website even loads. This edge function can inspec headers and log:

```js 

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const ip = request.headers.get('cf-connecting-ip');
  const geo = p
    country: request.headers.get('cf-ipcountry'),
    city: request.cf.city,
    region: request.cf.region,
    latitude: request.cf.latitude,
    longitude: request.cf.longitude
  };
  const referrer = request.headers.get('referer');
  console.log({ ip, geo, referrer });
  return fetch(request);
}

```

📌 Result: You now know the user's location, IP, and where they came from.

2. Device & Browser Fingerprinting – FingerprintJS

FingerprintJS is a powerful library that uses over 100 signals to uniquely identify users including their browser, OS, screen resolution, installed fonts, and more.


```html 

<script src="https://openfpcdn.io/fingerprintjs/v4"></script>
<script>
  FingerprintJS.load().then(fp => {
    fp.get().then(result => {
      console.log(result.visitorId); // Unique fingerprint
      console.log(result.components); // Device/browser data
    });
  });
</script>

```

📌 Result: Even if the IP changes, you can track a user across sessions and networks.


3. UI Interaction Monitoring – OpenReplay

Want to see exactly what a user clicked, hovered, or typed? OpenReplay gives you a screen recording-like playback of user behavior. But it's all code-based.

```html

<script>
  window.__openreplay__ = { projectKey: "YOUR_PROJECT_KEY" };
  (function(A,s,a,y,e,r){
    r=window.OpenReplay=[e=>r.push(e)],r.push=A;
    s=document.createElement('script');s.src=y;s.async=1;
    document.getElementsByTagName('head')[0].appendChild(s);
  })(window.__openreplay__, 0, 0, "https://static.openreplay.com/latest.js");
</script>

```
📌 Result: Full replay of user sessions — mouse movement, scrolls, and clicks.

4. General Analytics – Google Analytics (GA4)

Even though GA is well-known, it still offers an essential layer of tracking: session duration, bounce rate, and traffic sources. When combined with the above tools, it fills in behavioral context.


```html

<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-XXXXXXX');
</script>

```

📌 Result: Tracks demographics, engagement, and conversions.


## What This Means for the Average User

If a website uses all of these tools together, here’s what they can potentially know about you:


| Category       | What They Can Know                          |
| -------------- | ------------------------------------------- |
| IP & Geo       | Your country, city, ISP                     |
| Device/Browser | Your OS, screen size, browser extensions    |
| Behavior       | Where you clicked, hovered, scrolled        |
| Identity       | Unique fingerprint across visits/sessions   |
| Journey        | Where you came from and where you went next |

This doesn’t even require login or cookies. Even if you block cookies or use incognito mode, fingerprinting and server-side logs still identify you.

# Countermeasures: How to Reclaim Your Privacy

🔒 1. Use a VPN or Tor

Hides your real IP and location. Combine with other tools for stronger privacy.

🧑‍🎨 2. Browser Hardening

- Use Firefox with privacy add-ons (uBlock Origin, Privacy Badger, CanvasBlocker)
- Or try Brave, which has fingerprinting defenses built-in

🛑 3. Block Scripts

Use tools like:

- uMatrix or NoScript to prevent 3rd-party JS from loading
- LocalCDN to serve known libraries from your device

🧼 4. Regularly Clear Site Data

This breaks some tracking, though fingerprinting still works.

🕵️ 5. Try Anti-Fingerprinting Browsers

- Tor Browser resists fingerprinting by standardizing browser characteristics
- Librewolf is a privacy-focused Firefox fork

⚠️ Bonus: Watch for CNAME Cloaking

- Trackers can bypass ad blockers by disguising themselves as first-party domains.



Website tracking has become invisible and pervasive — often happening without consent or awareness. While tools like Cloudflare Workers, FingerprintJS, OpenReplay, and Google Analytics are powerful and free, their combined use shows how deeply a user can be profiled.

The good news? Awareness is the first defense. You don’t need to go off-grid to regain control — just make some smart changes.


Stay private, stay smart. The internet remembers — but you can make it forget.
