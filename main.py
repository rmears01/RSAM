from flask import Flask, request, render_template, redirect, url_for
import requests, rsa, threading, json, logging, socket
from tkinter import *

#simple rsa functions
def generate_keys():
    public_key, private_key = rsa.newkeys(1024)
    return [public_key,private_key]
def encrypt(message, public_key):
    return rsa.encrypt(message.encode(), public_key)
def decrypt(message, private_key):
    return rsa.decrypt(message, private_key).decode()

app = Flask(__name__)

#send message
def send_message(message, server):
    #remove / from end of url
    if server[-1] == "/":
        server = server[:-1]
    
    #get your private key
    with open("keys/private.pem", "rb") as file:
        private_key = rsa.PrivateKey.load_pkcs1(file.read())
        file.close()

    #get the public key of the server
    public_key = rsa.PublicKey.load_pkcs1(requests.get(server + "/getKey").text)
   
    #create and save the signature
    signature = rsa.sign(message.encode(), private_key, 'SHA-512')
    with open("outgoing/signature", "wb") as file:
        file.write(signature)
        file.close()

    #save encrypted message
    message = encrypt(message, public_key)
    with open("outgoing/message", "wb") as file:
        file.write(message)
        file.close()

    #send encrypted message
    files = {
            'message': open('outgoing/message','rb'),
            'signature': open('outgoing/signature','rb'),
            'public key': open('keys/public.pem','rb')
            }
    return(requests.post(server + "/recv", files=files).text)



#main thread
def main():
    choice = input("generate new keyset? (y/n):")
    
    if choice.lower() == "y":
        #create new keyset
        keys = generate_keys()
        with open("keys/public.pem", "wb") as file:
            file.write(keys[0].save_pkcs1("PEM"))
            file.close()
        with open("keys/private.pem", "wb") as file:
            file.write(keys[1].save_pkcs1("PEM"))
            file.close()

    #read the keys from the files
    with open("keys/public.pem", "rb") as file:
        public_key = rsa.PublicKey.load_pkcs1(file.read())
        file.close()
    with open("keys/private.pem", "rb") as file:
        private_key = rsa.PrivateKey.load_pkcs1(file.read())
        file.close()

    server = input("url or ip of the recieving client:")
    while True:
        #get the message from the user
        message = input("message:")
        if server[-1] == "/":
            server = server[:-1]
        print(send_message(message, server))


        


@app.route('/', methods=["GET"])
def index():
    return """
<head>
    <title>RSAM</title>
</head>
    
<body>

    <form action="/send" method="post">
        <label for="server">server:</label><br>
        <input type="text" id="server" name="server"><br>
        
        <label for="msg">send:</label><br>
        <input type="text" id="msg" name="msg">
    
        <input type="submit" value="Submit">
    </form>

</body>
    """

@app.route('/send',methods = ['POST', 'GET'])
def sendMsg():
    if request.method == 'POST':
        message = request.form["msg"]
        server = request.form["server"]
        print(f"{server}\n{message}")
        
        print(send_message(message, server))
        return redirect(url_for("index"))
    else:
        return redirect(url_for("index"))
    

@app.route('/getKey')
def getKey():
    #send public key
    with open("keys/public.pem", "rb") as file:
        public_key = rsa.PublicKey.load_pkcs1(file.read())
        file.close()
    return public_key.save_pkcs1("PEM")

@app.route('/recv', methods=["POST"])
def recv():
    #save the files
    messageFile = request.files["message"]
    signatureFile = request.files["signature"]
    pubKeyFile = request.files["public key"]
    messageFile.save("incoming/recv-message")
    signatureFile.save("incoming/recv-signature")
    pubKeyFile.save("incoming/recv-public.pem")

    #decrypt the message
    with open("keys/private.pem", "rb") as file:
        private_key = rsa.PrivateKey.load_pkcs1(file.read())
        file.close()
    with open("incoming/recv-message", "rb") as file:
        message = decrypt(file.read(), private_key)
        file.close()

    #check the signature
    with open("incoming/recv-signature", "rb") as file:
        signature = file.read()
        file.close()
    with open("incoming/recv-public.pem", "rb") as file:
        recieved_public_key = rsa.PublicKey.load_pkcs1(file.read())
        file.close()
    if rsa.verify(message.encode(), signature, recieved_public_key) == "SHA-512":
        #write the message to messages.log
        with open("messages.log", "a") as file:
            file.write(message + "\n")
            file.close()
        return "success"
    else:
        print("fail")
        return "fail"

main = threading.Thread(target=main, daemon=True)
main.start()
if __name__ == '__main__':
  app.run(host='0.0.0.0', port=80)





