import os
import boto3

html1 = '''
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
<script></script>
</head>    
<body>    
    <center> <h1> ProDesigner Page - in progress </h1> </center>   
    <form>  
        <div class="container"> 
'''

format_html = '''
            <label><a href="/mods">Only for moderators</a></label><!-- (Only role {} can get access) --><br>
            <label><a href="/flag">flag</a></label>
'''

html2 = '''
        </div>   
    </form>     
</body>
</html>
'''
ssm = boto3.client('ssm')

def lambda_handler(event, context):
    role_name = os.environ.get('ROLE_NAME', 'fishy_moderator')
    print(f"Role_name: {role_name}")

    response = html1 + format_html.format(role_name) + html2
    return  {
        "statusCode": 200,
        "body": response,
        "headers": {
            "Content-Type": "text/html"
        }
    }