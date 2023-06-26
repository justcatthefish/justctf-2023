import os

html1 = """
<!DOCTYPE html>   
<html>   
<head>  
<meta name="viewport" content="width=device-width, initial-scale=1">  
<title> Login Page </title>  
<style>   
Body {  
  font-family: Calibri, Helvetica, sans-serif;  
  background-color: pink;  
}  
button {   
       background-color: #4CAF50;   
       width: 100%;  
        color: orange;   
        padding: 15px;   
        margin: 10px 0px;   
        border: none;   
        cursor: pointer;   
         }   
 form {   
        border: 3px solid #f1f1f1;   
    }   
 input[type=text], input[type=password] {   
        width: 100%;   
        margin: 8px 0;  
        padding: 12px 20px;   
        display: inline-block;   
        border: 2px solid green;   
        box-sizing: border-box;   
    }  
 button:hover {   
        opacity: 0.7;   
    }   
  .cancelbtn {   
        width: auto;   
        padding: 10px 18px;  
        margin: 10px 5px;  
    }   
        
     
 .container {   
        padding: 25px;   
        background-color: lightblue;  
    }   
</style>
<script src="https://sdk.amazonaws.com/js/aws-sdk-2.1386.0.min.js"></script>
<!-- This script is not working, #TODO repair later -->
<script>
"""

js = "function _0x5e67(_0x57b88e,_0x353198){const _0xadc2a=_0xadc2();return _0x5e67=function(_0x5e6777,_0x595fa7){_0x5e6777=_0x5e6777-0x150;let _0x13d171=_0xadc2a[_0x5e6777];return _0x13d171;},_0x5e67(_0x57b88e,_0x353198);}function _0xadc2(){const _0x3081dc=['3714060biHjum','update','10400FgJKbU','4279289TxWcLy','Error:\x20','430AOcJOb','value','5174375nPmXOV','eu-west-1','log','Success!','1001286eHduAg','password','1314iRuJGk','This\x20script\x20is\x20not\x20working,\x20#TODO\x20repair\x20later','getElementById','8577mVyJTT','953970ZzEKjO','config',"+f"'{os.environ.get('IDENTITY_POOL_ID')}'"+","+f"'{os.environ.get('USER_POOL_ID')}'"+"];_0xadc2=function(){return _0x3081dc;};return _0xadc2();}(function(_0x38460e,_0x569ada){const _0x5d42c2=_0x5e67,_0x57800e=_0x38460e();while(!![]){try{const _0x575928=-parseInt(_0x5d42c2(0x154))/0x1*(parseInt(_0x5d42c2(0x15c))/0x2)+parseInt(_0x5d42c2(0x160))/0x3+-parseInt(_0x5d42c2(0x164))/0x4+parseInt(_0x5d42c2(0x156))/0x5+-parseInt(_0x5d42c2(0x15a))/0x6+-parseInt(_0x5d42c2(0x152))/0x7+-parseInt(_0x5d42c2(0x151))/0x8*(-parseInt(_0x5d42c2(0x15f))/0x9);if(_0x575928===_0x569ada)break;else _0x57800e['push'](_0x57800e['shift']());}catch(_0x5927a9){_0x57800e['push'](_0x57800e['shift']());}}}(_0xadc2,0x931a4));function login(){const _0x5416c2=_0x5e67;AWS[_0x5416c2(0x161)][_0x5416c2(0x150)]({'region':_0x5416c2(0x157)});const _0xd1dd90={'IdentityPool':_0x5416c2(0x162),'UserPool':_0x5416c2(0x163)},_0x1be46b={'AuthFlow':'USER_SRP_AUTH','ClientId':"+f"'{os.environ.get('CLIENT_ID')}'"+",'AuthParameters':{'USERNAME':document['getElementById']('username')['value'],'PASSWORD':document[_0x5416c2(0x15e)](_0x5416c2(0x15b))[_0x5416c2(0x155)]}};try{var _0x594dec=new AWS['CognitoIdentityServiceProvder']();}catch(_0x44a14f){console[_0x5416c2(0x158)](_0x5416c2(0x15d)),console['log'](_0x44a14f);}_0x594dec['initiateAuth'](_0x1be46b,function(_0x4c92b3,_0x43ebe2){const _0x12133a=_0x5416c2;_0x4c92b3?alert(_0x12133a(0x153)+_0x4c92b3):alert(_0x12133a(0x159));});}"

html2 = """
</script>
</head>    
<body>    
    <center> <h1> ProDesigner Login Form </h1> </center>   
    <form>  
        <div class="container">   
            <label>Username: </label>   
            <input type="text" placeholder="Enter Username" name="username" id="username" required>  
            <label>Password: </label>   
            <input type="password" placeholder="Enter Password" name="password" id="password" required>  
            <button onclick="login()">Login</button>   
            <input type="checkbox" checked="checked"> Remember me <!-- (I'm not sure if this does anything) -->
            <!--<label><a href="/ctf/home">After login</a></label><br>-->
            <!--<label><a href="/ctf/mods">For mods</a></label><br>-->
        </div>   
    </form>  
</body>
</html>
"""

def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "body": html1 + js + html2,
        "headers": {
            "Content-Type": "text/html"
        }
    }